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
)

// Exporter exports the conntrack stats cached by ctstats, with the endpoints
// of their addresses resolved.
type Exporter struct {
	stats    *ctstats.Cache
	epGetter resolverTypes.EndpointGetter

	mu   lock.Mutex
	last *Snapshot
}

func NewExporter(stats *ctstats.Cache, epGetter resolverTypes.EndpointGetter) *Exporter {
	return &Exporter{stats: stats, epGetter: epGetter}
}

// Snapshot returns the current conntrack stats. Endpoints are resolved only
// when the underlying ctstats.Snapshot changes, i.e. once per cache refresh.
// The returned Snapshot is shared and must not be modified.
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

// resolve resolves the endpoint of every address in stats, once per address.
// The destination of a service entry is skipped, as it is the address of a
// service rather than of an endpoint. Endpoints are resolved at refresh time,
// not when a connection is garbage collected: those no longer alive may thus be
// unresolved, or resolved to an endpoint that later reused their address.
func (e *Exporter) resolve(stats *ctstats.Snapshot) *Snapshot {
	s := &Snapshot{
		stats:     stats,
		endpoints: hubblectstats.NewEndpointDedup(),
		indices:   make(map[netip.Addr]*uint32),
	}
	resolve := func(addr netip.Addr) {
		if _, done := s.indices[addr]; done {
			return
		}
		var idx *uint32
		if i, ok := s.endpoints.Index(e.epGetter.ResolveEndpoint(addr, 0, resolverTypes.DatapathContext{})); ok {
			idx = &i
		}
		s.indices[addr] = idx
	}
	for t := range stats.Deduplicated() {
		resolve(t.Src)
		if !isService(t) {
			resolve(t.Dst)
		}
	}
	return s
}

// isService returns whether t is a service entry, which only tracks the packets
// sent to a service address before they are translated to a backend.
func isService(t ctstats.Tuple) bool {
	return t.Flags&ctstats.TupleFlagService != 0
}

// Snapshot is a ctstats.Snapshot along with the resolved endpoints of the
// addresses of its connections.
type Snapshot struct {
	stats     *ctstats.Snapshot
	endpoints *hubblectstats.EndpointDedup
	// indices maps an address to the index of its endpoint, nil if unresolved.
	indices map[netip.Addr]*uint32
}

func (s *Snapshot) Endpoints() iter.Seq[*conntrackpb.IndexedEndpoint] {
	return hubblectstats.IndexedEndpoints(s.endpoints)
}

// Entries yields one entry per connection, without the TUPLE_F_IN mirrors (see
// ctstats.Snapshot.Deduplicated).
func (s *Snapshot) Entries() iter.Seq[*conntrackpb.Entry] {
	return func(yield func(*conntrackpb.Entry) bool) {
		for t, e := range s.stats.Deduplicated() {
			entry := toProto(t, e)
			entry.SourceEndpointIndex = s.indices[t.Src]
			if !isService(t) {
				entry.DestinationEndpointIndex = s.indices[t.Dst]
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
