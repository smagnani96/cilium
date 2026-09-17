// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package conntrack

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/cilium/cilium/pkg/hubble/observer/conntrack/types"
	resolverTypes "github.com/cilium/cilium/pkg/hubble/resolver/types"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/u8proto"
	"golang.org/x/sync/singleflight"

	observerpb "github.com/cilium/cilium/api/v1/observer"
)

var ErrExporterDisabled = fmt.Errorf("conntrack exporter is disabled")

// ctExporter is responsible for exporting conntrack entries from the datapath.
type ctExporter struct {
	cfg      Config
	ctMaps   ctmap.CTMaps
	logger   *slog.Logger
	epGetter resolverTypes.EndpointGetter

	snapshot atomic.Pointer[Snapshot]
	refresh  singleflight.Group
}

// ctAggregationKey represents the key used to aggregate conntrack entries.
// It basically discards the source port, considering only the 4 tuple
// (source IP, destination IP, destination port, protocol).
type ctAggregationKey struct {
	sourceIP        netip.Addr
	destinationIP   netip.Addr
	destinationPort uint16
	protocol        u8proto.U8proto
}

// newConntrackExporter creates a new ConntrackExporter with the given parameters.
func newConntrackExporter(
	cfg Config,
	ctMaps ctmap.CTMaps,
	log *slog.Logger,
	epGetter resolverTypes.EndpointGetter,
) *ctExporter {
	return &ctExporter{
		cfg:      cfg,
		ctMaps:   ctMaps,
		logger:   log,
		epGetter: epGetter,
	}
}

// GetConntrackSnapshot dumps a snapshot of the node's datapath conntrack maps.
// It returns an error if the exporter is disabled.
func (c *ctExporter) GetConntrackSnapshot(ctx context.Context) (*types.Snapshot, error) {
	if c == nil || !c.cfg.EnableCTSnapshot {
		return nil, ErrExporterDisabled
	}

	if snap := c.cachedSnapshot(); snap != nil {
		return snap, nil
	}

	v, err, _ := c.refresh.Do("", func() (any, error) {
		// Someone else may have refreshed it between our check above and
		// winning the singleflight call.
		if snap := c.cachedSnapshot(); snap != nil {
			return snap, nil
		}

		snap, err := c.dumpSnapshot(ctx)
		if err != nil {
			return nil, err
		}

		c.snapshot.Store(snap)
		return snap, nil
	})
	if err != nil {
		return nil, err
	}
	return v.(*Snapshot), nil
}

// cachedSnapshot returns the cached snapshot if it is still valid.
func (c *ctExporter) cachedSnapshot() *Snapshot {
	snap := c.snapshot.Load()
	if snap != nil && time.Since(snap.ComputedAt) < c.cfg.ConntrackCacheTTL {
		return snap
	}
	return nil
}

// dumpSnapshot walks the datapath conntrack maps and creates a new snapshot.
func (c *ctExporter) dumpSnapshot(ctx context.Context) (*types.Snapshot, error) {
	entries := make(map[ctAggregationKey]*observerpb.ConntrackEntry)

	for _, m := range c.ctMaps.ActiveMaps() {
		err := m.DumpEntries(ctx, func(key ctmap.CtKey, val *ctmap.CtEntry) bool {
			aggregateCtEntry(entries, key, val, c.epGetter)
			return true
		})
		if err != nil {
			return nil, err
		}
	}

	snap := &types.Snapshot{
		Entries:    make([]*observerpb.ConntrackEntry, 0, len(entries)),
		ComputedAt: time.Now(),
	}
	for _, e := range entries {
		snap.Entries = append(snap.Entries, e)
	}
	return snap, nil
}

// aggregateCtKey generates the aggregation key for a given conntrack key.
// It returns the key and a boolean indicating whether the key could be aggregated.
//
// The aggregation key is derived from the original 5-tuple of the connection,
// but it ignores the source port. For TUPLE_F_SERVICE entries, the addresses
// are stored in natural (not reversed) order and the ports are swapped:
// SourceAddr:DestPort is the real client, DestAddr:SourcePort is the service frontend.
func aggregateCtKey(key ctmap.CtKey) (ctAggregationKey, bool) {
	var srcAddr, dstAddr netip.Addr
	var dstPort uint16
	var protocol u8proto.U8proto

	switch k := key.ToHost().(type) {
	case *ctmap.CtKey4Global:
		if k.Flags&ctmap.TUPLE_F_SERVICE != 0 {
			srcAddr, dstAddr = k.SourceAddr.Addr(), k.DestAddr.Addr()
			dstPort = k.SourcePort
		} else {
			srcAddr, dstAddr = k.DestAddr.Addr(), k.SourceAddr.Addr()
			dstPort = k.DestPort
		}
		protocol = k.NextHeader
	case *ctmap.CtKey6Global:
		if k.Flags&ctmap.TUPLE_F_SERVICE != 0 {
			srcAddr, dstAddr = k.SourceAddr.Addr(), k.DestAddr.Addr()
			dstPort = k.SourcePort
		} else {
			srcAddr, dstAddr = k.DestAddr.Addr(), k.SourceAddr.Addr()
			dstPort = k.DestPort
		}
		protocol = k.NextHeader
	default:
		return ctAggregationKey{}, false
	}

	return ctAggregationKey{srcAddr, dstAddr, dstPort, protocol}, true
}

// aggregateCtEntry aggregates a single conntrack entry into the provided map
// using the computed aggregation key. While aggregating, it computes unresolved
// data (e.g., endpoint) if needed.
func aggregateCtEntry(
	entries map[ctAggregationKey]*observerpb.ConntrackEntry,
	key ctmap.CtKey,
	val *ctmap.CtEntry,
	epGetter resolverTypes.EndpointGetter,
) {
	aggregateKey, ok := aggregateCtKey(key)
	if !ok {
		return
	}

	e, ok := entries[aggregateKey]
	if !ok {
		e = &observerpb.ConntrackEntry{
			SourceIp:        aggregateKey.sourceIP.String(),
			DestinationIp:   aggregateKey.destinationIP.String(),
			DestinationPort: uint32(aggregateKey.destinationPort),
			Protocol:        uint32(aggregateKey.protocol),
		}
		if epGetter != nil {
			dpContext := resolverTypes.DatapathContext{}
			e.Source = epGetter.ResolveEndpoint(aggregateKey.sourceIP, val.SourceSecurityID, dpContext)
			e.Destination = epGetter.ResolveEndpoint(aggregateKey.destinationIP, 0, dpContext)
		}
		entries[aggregateKey] = e
	}

	e.Packets += val.Packets
	e.Bytes += val.Bytes
	e.Count += 1
}
