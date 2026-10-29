// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package ctstats

import (
	"errors"
	"iter"
	"slices"

	conntrackpb "github.com/cilium/cilium/api/v1/conntrack"
)

// View is what a Query applies to: the Snapshot of an agent or of Hubble Relay.
type View interface {
	Entries() iter.Seq[*conntrackpb.Entry]
	Endpoints() iter.Seq[*conntrackpb.IndexedEndpoint]
	Services() iter.Seq[*conntrackpb.IndexedService]
	Nodes() iter.Seq[*conntrackpb.IndexedNode]
}

// Query is the filtering of a GetStatsRequest. Applying it leaves the cached
// snapshot untouched, as other callers may query it differently.
type Query struct {
	filter *filter
}

// NewQuery validates req, so that an invalid one is rejected before any work.
func NewQuery(req *conntrackpb.GetStatsRequest) (*Query, error) {
	f := req.GetFilter()
	if !req.GetResolve() && filterUsesResolved(f) {
		return nil, errors.New("filtering by endpoint, service or node requires resolve")
	}
	flt, err := newFilter(f)
	if err != nil {
		return nil, err
	}
	return &Query{filter: flt}, nil
}

func (q *Query) Apply(v View) View {
	if q.filter != nil {
		v = q.filter.apply(v)
	}
	return v
}

type view struct {
	src                    View
	entries                []*conntrackpb.Entry
	endpoints, svcs, nodes map[uint32]bool
}

func newView(src View, entries []*conntrackpb.Entry) *view {
	v := &view{src: src, entries: entries, endpoints: map[uint32]bool{}, svcs: map[uint32]bool{}, nodes: map[uint32]bool{}}
	mark := func(m map[uint32]bool, idx ...*uint32) {
		for _, i := range idx {
			if i != nil {
				m[*i] = true
			}
		}
	}
	for _, e := range entries {
		mark(v.endpoints, e.SourceEndpointIndex, e.DestinationEndpointIndex)
		mark(v.svcs, e.DestinationServiceIndex)
		mark(v.nodes, e.SourceNodeIndex, e.DestinationNodeIndex)
	}
	return v
}

func (v *view) Entries() iter.Seq[*conntrackpb.Entry] { return slices.Values(v.entries) }

func (v *view) Endpoints() iter.Seq[*conntrackpb.IndexedEndpoint] {
	return func(yield func(*conntrackpb.IndexedEndpoint) bool) {
		for ep := range v.src.Endpoints() {
			if v.endpoints[ep.GetIndex()] && !yield(ep) {
				return
			}
		}
	}
}

func (v *view) Services() iter.Seq[*conntrackpb.IndexedService] {
	return func(yield func(*conntrackpb.IndexedService) bool) {
		for svc := range v.src.Services() {
			if v.svcs[svc.GetIndex()] && !yield(svc) {
				return
			}
		}
	}
}

func (v *view) Nodes() iter.Seq[*conntrackpb.IndexedNode] {
	return func(yield func(*conntrackpb.IndexedNode) bool) {
		for n := range v.src.Nodes() {
			if v.nodes[n.GetIndex()] && !yield(n) {
				return
			}
		}
	}
}
