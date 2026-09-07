// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package conntrack

import (
	"context"
	"log/slog"
	"net/netip"
	"sync/atomic"

	"github.com/cilium/cilium/pkg/hubble/mapexporter/common"
	resolverTypes "github.com/cilium/cilium/pkg/hubble/resolver/types"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/rate"
	"github.com/cilium/cilium/pkg/u8proto"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	observerpb "github.com/cilium/cilium/api/v1/observer"
)

type ConntrackExporter struct {
	cfg      Config
	ctMaps   ctmap.CTMaps
	logger   *slog.Logger
	epGetter resolverTypes.EndpointGetter

	clock         common.BPFClock
	inFlight      atomic.Bool
	ctRateLimiter *rate.Limiter
}

func newConntrackExporter(
	cfg Config,
	ctMaps ctmap.CTMaps,
	log *slog.Logger,
	epGetter resolverTypes.EndpointGetter,
) *ConntrackExporter {
	clock, err := common.NewBPFClock()
	if err != nil {
		// The dump is still useful without the wall-clock timestamps.
		log.Warn("Failed to determine clock source", slog.String("error", err.Error()))
	}
	var rateLimiter *rate.Limiter
	if cfg.ConntrackRateLimit > 0 {
		rateLimiter = rate.NewLimiter(cfg.ConntrackRateLimit, 1)
	}
	return &ConntrackExporter{
		cfg:           cfg,
		ctMaps:        ctMaps,
		logger:        log,
		epGetter:      epGetter,
		clock:         clock,
		ctRateLimiter: rateLimiter,
	}
}

// GetConntrackEntries dumps the node's datapath conntrack maps and yields each
// entry to the provided callback. It returns an error if the exporter is
// disabled.
func (c *ConntrackExporter) GetConntrackEntries(ctx context.Context, req *observerpb.GetConntrackEntriesRequest, yield func(*observerpb.ConntrackEntry) bool) error {
	if c == nil || !c.cfg.EnableConntrack {
		return common.ErrExporterDisabled
	}
	if !c.inFlight.CompareAndSwap(false, true) {
		return common.ErrExportInProgress
	}
	defer c.inFlight.Store(false)
	if c.cfg.ConntrackRateLimit > 0 && !c.ctRateLimiter.Allow() {
		return common.ErrExportRateLimitExceeded
	}

	var n uint64

	for _, m := range c.ctMaps.ActiveMaps() {
		err := m.DumpEntries(ctx, func(key ctmap.CtKey, val *ctmap.CtEntry) bool {
			if !yield(ctEntryToProto(key, val, c.clock, c.cfg.EnableConntrackEnrichment, c.epGetter)) {
				return false
			}
			n++
			return req.GetNumber() == 0 || n < req.GetNumber()
		})
		if err != nil {
			return err
		}
	}

	return nil
}

// ctEntryToProto converts a raw datapath conntrack entry into its protobuf representation.
func ctEntryToProto(
	key ctmap.CtKey,
	entry *ctmap.CtEntry,
	clock common.BPFClock,
	enrich bool,
	epGetter resolverTypes.EndpointGetter,
) *observerpb.ConntrackEntry {
	e := &observerpb.ConntrackEntry{
		Packets:        entry.Packets,
		Bytes:          entry.Bytes,
		ExpiresAt:      clock.ToWallClock(entry.Lifetime),
		Flags:          ctEntryFlagsToProto(entry.Flags),
		LastTxReportAt: clock.ToWallClock(entry.LastTxReport),
		LastRxReportAt: clock.ToWallClock(entry.LastRxReport),
	}

	var srcAddr, dstAddr netip.Addr
	var srcPort, dstPort uint16
	var tupleFlags uint8

	// The datapath's tuple stores addresses swapped relative to the real
	// packet (see the field doc comments on struct ipv{4,6}_ct_tuple in
	// bpf/lib/common.h). Ports are not part of that swap and are used as-is.
	switch k := key.ToHost().(type) {
	case *ctmap.CtKey4Global:
		srcAddr, dstAddr = k.DestAddr.Addr(), k.SourceAddr.Addr()
		srcPort, dstPort = k.SourcePort, k.DestPort
		e.Protocol = uint32(k.NextHeader)
		tupleFlags = k.Flags
	case *ctmap.CtKey6Global:
		srcAddr, dstAddr = k.DestAddr.Addr(), k.SourceAddr.Addr()
		srcPort, dstPort = k.SourcePort, k.DestPort
		e.Protocol = uint32(k.NextHeader)
		tupleFlags = k.Flags
	default:
		return e
	}

	e.SourceIp = srcAddr.String()
	e.DestinationIp = dstAddr.String()
	e.SourcePort = uint32(srcPort)
	e.DestinationPort = uint32(dstPort)
	if u8proto.U8proto(e.Protocol) == u8proto.TCP {
		e.Tcp = &observerpb.ConntrackEntryTCP{
			TxFlagsSeen: uint32(entry.TxFlagsSeen),
			RxFlagsSeen: uint32(entry.RxFlagsSeen),
		}
	}
	e.Direction = flowpb.TrafficDirection_EGRESS
	if tupleFlags&ctmap.TUPLE_F_IN != 0 {
		e.Direction = flowpb.TrafficDirection_INGRESS
	}
	e.Related = tupleFlags&ctmap.TUPLE_F_RELATED != 0
	e.ServiceEntry = tupleFlags&ctmap.TUPLE_F_SERVICE != 0

	// If enrichment is not requested, return early.
	if !enrich {
		return e
	}

	// Empty datapath context. We resolve purely by using the legit
	// source identity and destination address.
	dpContext := resolverTypes.DatapathContext{}
	if epGetter != nil {
		e.Source = epGetter.ResolveEndpoint(srcAddr, 0, dpContext)
		e.Destination = epGetter.ResolveEndpoint(dstAddr, entry.SourceSecurityID, dpContext)
	}

	return e
}

// ctEntryFlagsToProto converts the conntrack entry flags from the datapath
// representation to the protobuf representation.
func ctEntryFlagsToProto(flags uint16) *observerpb.ConntrackEntryFlags {
	return &observerpb.ConntrackEntryFlags{
		RxClosing:     flags&ctmap.RxClosing != 0,
		TxClosing:     flags&ctmap.TxClosing != 0,
		LbLoopback:    flags&ctmap.LBLoopback != 0,
		SeenNonSyn:    flags&ctmap.SeenNonSyn != 0,
		NodePort:      flags&ctmap.NodePort != 0,
		ProxyRedirect: flags&ctmap.ProxyRedirect != 0,
		DsrInternal:   flags&ctmap.DSRInternal != 0,
		FromL7Lb:      flags&ctmap.FromL7LB != 0,
		FromTunnel:    flags&ctmap.FromTunnel != 0,
	}
}
