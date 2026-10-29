// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

// Package ctstats converts the datapath conntrack stats cached by ctstats
// into the Hubble conntrack API.
package ctstats

import (
	"context"
	"iter"
	"net/netip"

	conntrackpb "github.com/cilium/cilium/api/v1/conntrack"
	"github.com/cilium/cilium/pkg/ctstats"
	hubblectstats "github.com/cilium/cilium/pkg/hubble/ctstats"
	resolverTypes "github.com/cilium/cilium/pkg/hubble/resolver/types"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/u8proto"
)

// Exporter exports the conntrack stats cached by ctstats, with the endpoints,
// services and nodes of their addresses resolved.
type Exporter struct {
	stats      *ctstats.Cache
	epGetter   resolverTypes.EndpointGetter
	svcGetter  resolverTypes.ServiceGetter
	nodeGetter resolverTypes.NodeGetter

	mu   lock.Mutex
	last *Snapshot
}

func NewExporter(
	stats *ctstats.Cache,
	epGetter resolverTypes.EndpointGetter,
	svcGetter resolverTypes.ServiceGetter,
	nodeGetter resolverTypes.NodeGetter,
) *Exporter {
	return &Exporter{stats: stats, epGetter: epGetter, svcGetter: svcGetter, nodeGetter: nodeGetter}
}

// Snapshot returns the current conntrack stats. Endpoints, services and nodes
// are resolved only when the underlying ctstats.Snapshot changes, i.e. once per
// cache refresh. The returned Snapshot is shared and must not be modified.
func (e *Exporter) Snapshot(ctx context.Context) (*Snapshot, error) {
	snap, err := e.stats.Snapshot(ctx)
	if err != nil {
		return nil, err
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	if e.last == nil || e.last.stats != snap {
		e.last = e.resolve(snap)
	}
	return e.last, nil
}

// resolve resolves the endpoints, services and nodes of the addresses in stats,
// once each. Only the destination of a service entry is a service address, the
// others are backends. As it happens at refresh time, a connection no longer
// alive may be unresolved, or resolved to an endpoint that reused its address.
func (e *Exporter) resolve(stats *ctstats.Snapshot) *Snapshot {
	s := &Snapshot{
		stats:       stats,
		endpoints:   hubblectstats.NewEndpointDedup(),
		indices:     make(map[netip.Addr]*uint32),
		services:    hubblectstats.NewServiceDedup(),
		svcIndices:  make(map[svcAddr]*uint32),
		nodes:       hubblectstats.NewNodeDedup(),
		nodeIndices: make(map[netip.Addr]*uint32),
	}
	resolveEndpoint := func(addr netip.Addr) {
		if _, done := s.indices[addr]; done {
			return
		}
		ep := e.epGetter.ResolveEndpoint(addr, 0, resolverTypes.DatapathContext{})
		var idx *uint32
		if i, ok := s.endpoints.Index(ep); ok {
			idx = &i
		}
		s.indices[addr] = idx

		// Only the addresses that are not pods may belong to a node.
		if ep.GetPodName() == "" {
			if i, ok := s.nodes.Index(e.nodeGetter.GetNodeByAddr(addr)); ok {
				s.nodeIndices[addr] = &i
			}
		}
	}
	resolveService := func(a svcAddr) {
		if _, done := s.svcIndices[a]; done {
			return
		}
		var idx *uint32
		if i, ok := s.services.Index(e.svcGetter.GetServiceByAddr(a.addr, a.port, u8proto.U8proto(a.proto))); ok {
			idx = &i
		}
		s.svcIndices[a] = idx
	}
	for t := range stats.Deduplicated() {
		resolveEndpoint(t.Src)
		if isService(t) {
			resolveService(svcAddr{t.Dst, t.DstPort, t.Proto})
		} else {
			resolveEndpoint(t.Dst)
		}
	}
	return s
}

type svcAddr struct {
	addr  netip.Addr
	port  uint16
	proto uint8
}

// isService returns whether t is a service entry, which only tracks the packets
// sent to a service address before they are translated to a backend.
func isService(t ctstats.Tuple) bool {
	return t.Flags&ctstats.TupleFlagService != 0
}

// Snapshot is a ctstats.Snapshot along with the resolved endpoints, services
// and nodes of the addresses of its connections.
type Snapshot struct {
	stats     *ctstats.Snapshot
	endpoints *hubblectstats.EndpointDedup
	// indices maps an address to the index of its endpoint, nil if unresolved.
	indices     map[netip.Addr]*uint32
	services    *hubblectstats.ServiceDedup
	svcIndices  map[svcAddr]*uint32
	nodes       *hubblectstats.NodeDedup
	nodeIndices map[netip.Addr]*uint32
}

func (s *Snapshot) Endpoints() iter.Seq[*conntrackpb.IndexedEndpoint] {
	return hubblectstats.IndexedEndpoints(s.endpoints)
}

func (s *Snapshot) Services() iter.Seq[*conntrackpb.IndexedService] {
	return hubblectstats.IndexedServices(s.services)
}

func (s *Snapshot) Nodes() iter.Seq[*conntrackpb.IndexedNode] {
	return hubblectstats.IndexedNodes(s.nodes)
}

// Entries lazily yields one entry per connection in the snapshot, with the
// TUPLE_F_IN mirrors dropped (see ctstats.Snapshot.Deduplicated), stopping as
// soon as the consumer stops ranging over the sequence.
func (s *Snapshot) Entries() iter.Seq[*conntrackpb.Entry] {
	return func(yield func(*conntrackpb.Entry) bool) {
		for t, e := range s.stats.Deduplicated() {
			entry := toProto(t, e)
			entry.SourceEndpointIndex = s.indices[t.Src]
			entry.SourceNodeIndex = s.nodeIndices[t.Src]
			if isService(t) {
				entry.DestinationServiceIndex = s.svcIndices[svcAddr{t.Dst, t.DstPort, t.Proto}]
			} else {
				entry.DestinationEndpointIndex = s.indices[t.Dst]
				entry.DestinationNodeIndex = s.nodeIndices[t.Dst]
			}
			if !yield(entry) {
				return
			}
		}
	}
}

func toProto(t ctstats.Tuple, e ctstats.Entry) *conntrackpb.Entry {
	return &conntrackpb.Entry{
		Key: &conntrackpb.Key{
			SourceIp:        t.Src.String(),
			SourcePort:      uint32(t.SrcPort),
			DestinationIp:   t.Dst.String(),
			DestinationPort: uint32(t.DstPort),
			Protocol:        uint32(t.Proto),
			Flags:           uint32(t.Flags),
		},
		Value: &conntrackpb.Value{
			RxPackets: e.RxPackets,
			TxPackets: e.TxPackets,
			RxBytes:   e.RxBytes,
			TxBytes:   e.TxBytes,
		},
		State: &conntrackpb.State{Alive: e.Alive},
	}
}
