// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package conntrack

import (
	"context"
	"errors"
	"iter"
	"log/slog"
	"net/netip"

	observerpb "github.com/cilium/cilium/api/v1/observer"
	"github.com/cilium/cilium/pkg/hubble/observer/conntrack/types"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/u8proto"
)

var ErrExporterDisabled = errors.New("conntrack stats exporter is disabled")

// ctStatsExporter is responsible for exporting conntrack stats from the datapath.
type ctStatsExporter struct {
	daemonCfg   *option.DaemonConfig
	ctStatsMaps ctmap.StatsMaps
	logger      *slog.Logger
}

func newCTStatsExporter(
	daemonCfg *option.DaemonConfig,
	ctStatsMaps ctmap.StatsMaps,
	log *slog.Logger,
) *ctStatsExporter {
	return &ctStatsExporter{
		daemonCfg:   daemonCfg,
		ctStatsMaps: ctStatsMaps,
		logger:      log,
	}
}

func (c *ctStatsExporter) Enabled() bool {
	return c != nil && c.daemonCfg != nil && c.daemonCfg.BPFConntrackAccounting
}

// GetConntrackStats dumps conntrack stats from the node's datapath conntrack maps.
func (c *ctStatsExporter) GetConntrackStats(ctx context.Context) (types.Stats, error) {
	if !c.Enabled() {
		return nil, ErrExporterDisabled
	}
	return c.dumpStats(ctx)
}

// mergeKey identifies the logical connection a conntrack entry belongs to,
// ignoring TUPLE_F_IN/TUPLE_F_OUT. The datapath can record the very same
// connection twice under identical 5-tuple fields but opposite IN/OUT
// flags when it is observed from two different hook points (see the
// TUPLE_F_IN/TUPLE_F_OUT comment in bpf/lib/conntrack.h); the two entries'
// RX/TX counters are then swapped mirror images of one another rather than
// additional traffic. TUPLE_F_SERVICE and TUPLE_F_RELATED are kept in the
// key since they identify genuinely different hops (pre-DNAT service
// frontend, related ICMP), not mirrors of the same flow.
//
// For same-node pod-to-pod traffic this mirroring comes from each endpoint's
// own bpf_lxc program independently running the shared ct_create4/ct_lookup4
// bookkeeping for the same physical packets (once as CT_EGRESS from the
// sender, once as CT_INGRESS on the receiver, cf. cil_from_container and
// cil_lxc_policy/cil_to_container) with no state shared between the two.
// Deduplicating in the datapath would require us to share signal (cb[] or mark)
// between the two hooks to reliably says "the peer's egress already
// accounted for this packet" without also miscounting genuine first-contact
// ingress (world/cross-node traffic with no local peer), and the closest
// viable signal (a new bit in CB_DELIVERY_FLAGS) only covers the default
// bpf-host-routing config, not the legacy enable_endpoint_routes redirect
// path or other diversions (loopback/hairpin, SRv6/VRF, proxy redirects).
// A Go-side safety net would still be required regardless. Given that,
// merging here is the single, always-correct place to do it; the datapath
// intentionally keeps writing one stats entry per CT entry, mirroring how
// the main CT map itself needs separate per-endpoint entries.
type mergeKey struct {
	srcAddr, dstAddr netip.Addr
	srcPort, dstPort uint16
	protocol         u8proto.U8proto
	flags            uint8
}

func newMergeKey(srcAddr, dstAddr netip.Addr, srcPort, dstPort uint16, protocol u8proto.U8proto, flags uint8) mergeKey {
	return mergeKey{srcAddr, dstAddr, srcPort, dstPort, protocol, flags &^ ctmap.TUPLE_F_IN}
}

func (c *ctStatsExporter) dumpStats(ctx context.Context) (*ctStats, error) {
	stats := &ctStats{entries: make(map[mergeKey]*ctEntry)}

	err := c.ctStatsMaps.DumpEntries(ctx, func(key ctmap.CtKey, value ctmap.StatsValues) bool {
		stats.merge(key, value)
		return true
	})
	if err != nil {
		return nil, err
	}

	return stats, nil
}

// merge folds a raw conntrack map entry into the stats, collapsing
// TUPLE_F_IN/TUPLE_F_OUT mirror pairs (see mergeKey) into a single
// canonical (TUPLE_F_OUT) entry instead of keeping both or summing their
// counters.
func (c *ctStats) merge(key ctmap.CtKey, values ctmap.StatsValues) {
	srcAddr, dstAddr, srcPort, dstPort, protocol, flags, ok := ctKeyToTuple(key)
	if !ok {
		return
	}

	mk := newMergeKey(srcAddr, dstAddr, srcPort, dstPort, protocol, flags)
	if existing, found := c.entries[mk]; found && existing.flags&ctmap.TUPLE_F_IN == 0 {
		// this entry is the TUPLE_F_IN mirror of already existing TUPLE_F_OUT entry.
		return
	}

	c.entries[mk] = &ctEntry{
		srcAddr:  srcAddr,
		dstAddr:  dstAddr,
		srcPort:  srcPort,
		dstPort:  dstPort,
		protocol: protocol,
		flags:    flags,
		value:    values.Aggregate(),
	}
}

type ctEntry struct {
	srcAddr, dstAddr netip.Addr
	srcPort, dstPort uint16
	protocol         u8proto.U8proto
	flags            uint8
	value            ctmap.StatsValue
}

type ctStats struct {
	entries map[mergeKey]*ctEntry
}

// Entries lazily yields one ConntrackStatsEntry per merged connection: it does
// not allocate or populate a slice of all entries upfront, and stops
// walking c.entries as soon as the consumer stops ranging over the
// sequence.
func (c *ctStats) Entries() iter.Seq[*observerpb.ConntrackStatsEntry] {
	return func(yield func(*observerpb.ConntrackStatsEntry) bool) {
		for _, e := range c.entries {
			entry := CTEntryToProto(e)
			if !yield(entry) {
				return
			}
		}
	}
}

func CTEntryToProto(e *ctEntry) *observerpb.ConntrackStatsEntry {
	return &observerpb.ConntrackStatsEntry{
		Key: &observerpb.ConntrackStatsKey{
			SourceIp:        e.srcAddr.String(),
			SourcePort:      uint32(e.srcPort),
			DestinationIp:   e.dstAddr.String(),
			DestinationPort: uint32(e.dstPort),
			Protocol:        uint32(e.protocol),
			Flags:           uint32(e.flags),
		},
		Value: &observerpb.ConntrackStatsValue{
			RxPackets: e.value.RxPackets,
			TxPackets: e.value.TxPackets,
			RxBytes:   e.value.RxBytes,
			TxBytes:   e.value.TxBytes,
		},
	}
}

// ctKeyToTuple extracts the real client/server 5-tuple from a conntrack key.
//
// We already ignore TUPLE_F_SERVICE in the datapath (dir CT_SERVICE).
// For all other entries, addresses are swapped but ports are not:
// DestAddr:SourcePort is the real client, SourceAddr:DestPort is the real destination.
func ctKeyToTuple(key ctmap.CtKey) (
	srcAddr, dstAddr netip.Addr,
	srcPort, dstPort uint16,
	protocol u8proto.U8proto,
	flags uint8,
	ok bool,
) {
	switch k := key.ToHost().(type) {
	case *ctmap.CtKey4Global:
		srcAddr, dstAddr = k.DestAddr.Addr(), k.SourceAddr.Addr()
		srcPort, dstPort = k.SourcePort, k.DestPort
		protocol = k.NextHeader
		flags = k.Flags
	case *ctmap.CtKey6Global:
		srcAddr, dstAddr = k.DestAddr.Addr(), k.SourceAddr.Addr()
		srcPort, dstPort = k.SourcePort, k.DestPort
		protocol = k.NextHeader
		flags = k.Flags
	default:
		return netip.Addr{}, netip.Addr{}, 0, 0, 0, 0, false
	}
	return srcAddr, dstAddr, srcPort, dstPort, protocol, flags, true
}
