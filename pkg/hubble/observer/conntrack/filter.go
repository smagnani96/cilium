// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package conntrack

import (
	"iter"
	"net/netip"
	"slices"
	"strings"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	observerpb "github.com/cilium/cilium/api/v1/observer"
	"github.com/cilium/cilium/pkg/hubble/k8s"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// Filter drops every entry of stats that doesn't match f, along with any
// Endpoint/node no longer referenced by a surviving entry. If f is nil or
// every one of its fields is unset, stats is returned unmodified.
//
// Filter never mutates stats, nor the snapshot it was computed from, for the
// same reason Aggregate doesn't: different callers may filter the very same
// cached snapshot differently.
func Filter(stats Snapshot, f *observerpb.ConntrackFilter) Snapshot {
	matcher := newFilter(f)
	if matcher == nil {
		return stats
	}

	endpointsByIdx := make(map[uint32]*flowpb.Endpoint)
	for ep := range stats.Endpoints() {
		endpointsByIdx[ep.GetIndex()] = ep.GetEndpoint()
	}
	nodesByIdx := make(map[uint32]*observerpb.ConntrackStatsNode)
	for n := range stats.Nodes() {
		nodesByIdx[n.GetIndex()] = n
	}

	filtered := &filteredStats{
		stats:               stats,
		referencedEndpoints: make(map[uint32]bool),
		referencedNodes:     make(map[uint32]bool),
	}
	for e := range stats.Entries() {
		if !matcher.match(e, endpointsByIdx, nodesByIdx) {
			continue
		}
		filtered.entries = append(filtered.entries, e)
		if idx := e.GetSourceEndpointIndex(); idx != nil {
			filtered.referencedEndpoints[idx.GetValue()] = true
		}
		if idx := e.GetDestinationEndpointIndex(); idx != nil {
			filtered.referencedEndpoints[idx.GetValue()] = true
		}
		if idx := e.GetSourceNodeIndex(); idx != nil {
			filtered.referencedNodes[idx.GetValue()] = true
		}
		if idx := e.GetDestinationNodeIndex(); idx != nil {
			filtered.referencedNodes[idx.GetValue()] = true
		}
	}
	return filtered
}

// filter matches a ConntrackStatsEntry against a *observerpb.ConntrackFilter. A
// nil filter matches every entry.
type filter struct {
	sourceAddrs, destAddrs         []string
	sourcePrefixes, destPrefixes   []netip.Prefix
	sourcePorts, destPorts         []uint32
	protocols                      []uint32
	sourceEndpoints, destEndpoints []namespacedNameFilter
	sourceNodes, destNodes         []string
}

// namespacedNameFilter matches a namespace/name pair the same way "hubble
// observe"'s pod/service filters do: namespace, if set, must match exactly,
// and name, if set, is matched as a prefix.
type namespacedNameFilter struct {
	namespace, namePrefix string
}

func newNamespacedNameFilters(names []string) []namespacedNameFilter {
	filters := make([]namespacedNameFilter, 0, len(names))
	for _, name := range names {
		ns, prefix := k8s.ParseNamespaceName(name)
		filters = append(filters, namespacedNameFilter{namespace: ns, namePrefix: prefix})
	}
	return filters
}

func matchNamespacedName(ns, name string, filters []namespacedNameFilter) bool {
	if len(filters) == 0 {
		return true
	}
	if ns == "" && name == "" {
		return false
	}
	return slices.ContainsFunc(filters, func(f namespacedNameFilter) bool {
		return (f.namePrefix == "" || strings.HasPrefix(name, f.namePrefix)) && (f.namespace == "" || f.namespace == ns)
	})
}

// newFilter builds a matcher for f. It returns nil if f is nil or every one
// of its fields is unset, so callers can skip filtering entirely in the
// common case; malformed IP filters are treated as never matching, rather
// than rejected, since GetConntrackStatsRequest has no way to report an
// error back mid-stream.
func newFilter(f *observerpb.ConntrackFilter) *filter {
	if f == nil {
		return nil
	}
	if len(f.GetSourceIp()) == 0 && len(f.GetDestinationIp()) == 0 &&
		len(f.GetSourcePort()) == 0 && len(f.GetDestinationPort()) == 0 &&
		len(f.GetProtocol()) == 0 &&
		len(f.GetSourceEndpoint()) == 0 && len(f.GetDestinationEndpoint()) == 0 &&
		len(f.GetSourceNode()) == 0 && len(f.GetDestinationNode()) == 0 {
		return nil
	}

	mf := &filter{
		sourcePorts:     f.GetSourcePort(),
		destPorts:       f.GetDestinationPort(),
		protocols:       f.GetProtocol(),
		sourceEndpoints: newNamespacedNameFilters(f.GetSourceEndpoint()),
		destEndpoints:   newNamespacedNameFilters(f.GetDestinationEndpoint()),
		sourceNodes:     f.GetSourceNode(),
		destNodes:       f.GetDestinationNode(),
	}
	mf.sourceAddrs, mf.sourcePrefixes = splitIPFilter(f.GetSourceIp())
	mf.destAddrs, mf.destPrefixes = splitIPFilter(f.GetDestinationIp())
	return mf
}

// splitIPFilter splits ips into exact addresses and CIDR prefixes: each
// value is either an exact address (e.g. "10.0.0.1") or a CIDR range (e.g.
// "10.0.0.0/24"), mirroring the convention "hubble observe"'s IP filters
// use. A malformed value is dropped from both lists, so it can never match.
func splitIPFilter(ips []string) (addrs []string, prefixes []netip.Prefix) {
	for _, ip := range ips {
		if strings.Contains(ip, "/") {
			if prefix, err := netip.ParsePrefix(ip); err == nil {
				prefixes = append(prefixes, prefix)
			}
			continue
		}
		if _, err := netip.ParseAddr(ip); err == nil {
			addrs = append(addrs, ip)
		}
	}
	return addrs, prefixes
}

func matchIP(ip string, addrs []string, prefixes []netip.Prefix) bool {
	if len(addrs) == 0 && len(prefixes) == 0 {
		return true
	}
	if slices.Contains(addrs, ip) {
		return true
	}
	if len(prefixes) == 0 {
		return false
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	return slices.ContainsFunc(prefixes, func(p netip.Prefix) bool {
		return p.Contains(addr)
	})
}

// match reports whether e matches every field set on f. A nil f matches
// every entry.
func (f *filter) match(
	e *observerpb.ConntrackStatsEntry,
	endpointsByIdx map[uint32]*flowpb.Endpoint,
	nodesByIdx map[uint32]*observerpb.ConntrackStatsNode,
) bool {
	if f == nil {
		return true
	}
	if !matchIP(e.GetKey().GetSourceIp(), f.sourceAddrs, f.sourcePrefixes) {
		return false
	}
	if !matchIP(e.GetKey().GetDestinationIp(), f.destAddrs, f.destPrefixes) {
		return false
	}
	if len(f.sourcePorts) > 0 && !slices.Contains(f.sourcePorts, e.GetKey().GetSourcePort()) {
		return false
	}
	if len(f.destPorts) > 0 && !slices.Contains(f.destPorts, e.GetKey().GetDestinationPort()) {
		return false
	}
	if len(f.protocols) > 0 && !slices.Contains(f.protocols, e.GetKey().GetProtocol()) {
		return false
	}
	if !matchEndpoint(e.GetSourceEndpointIndex(), endpointsByIdx, f.sourceEndpoints) {
		return false
	}
	if !matchEndpoint(e.GetDestinationEndpointIndex(), endpointsByIdx, f.destEndpoints) {
		return false
	}
	if !matchNode(e.GetSourceNodeIndex(), nodesByIdx, f.sourceNodes) {
		return false
	}
	if !matchNode(e.GetDestinationNodeIndex(), nodesByIdx, f.destNodes) {
		return false
	}
	return true
}

func matchEndpoint(idx *wrapperspb.UInt32Value, endpointsByIdx map[uint32]*flowpb.Endpoint, filters []namespacedNameFilter) bool {
	if len(filters) == 0 {
		return true
	}
	if idx == nil {
		return false
	}
	ep := endpointsByIdx[idx.GetValue()]
	return matchNamespacedName(ep.GetNamespace(), ep.GetPodName(), filters)
}

func matchNode(idx *wrapperspb.UInt32Value, nodesByIdx map[uint32]*observerpb.ConntrackStatsNode, names []string) bool {
	if len(names) == 0 {
		return true
	}
	if idx == nil {
		return false
	}
	n := nodesByIdx[idx.GetValue()]
	return slices.Contains(names, n.GetName())
}

// filteredStats is a Snapshot backed by an already-filtered slice of
// entries, and the subset of the original stats' Endpoints/Nodes still
// referenced by them.
type filteredStats struct {
	stats               Snapshot
	entries             []*observerpb.ConntrackStatsEntry
	referencedEndpoints map[uint32]bool
	referencedNodes     map[uint32]bool
}

func (s *filteredStats) Entries() iter.Seq[*observerpb.ConntrackStatsEntry] {
	return func(yield func(*observerpb.ConntrackStatsEntry) bool) {
		for _, e := range s.entries {
			if !yield(e) {
				return
			}
		}
	}
}

func (s *filteredStats) Endpoints() iter.Seq[*observerpb.ConntrackStatsEndpoint] {
	return func(yield func(*observerpb.ConntrackStatsEndpoint) bool) {
		for ep := range s.stats.Endpoints() {
			if s.referencedEndpoints[ep.GetIndex()] && !yield(ep) {
				return
			}
		}
	}
}

func (s *filteredStats) Nodes() iter.Seq[*observerpb.ConntrackStatsNode] {
	return func(yield func(*observerpb.ConntrackStatsNode) bool) {
		for n := range s.stats.Nodes() {
			if s.referencedNodes[n.GetIndex()] && !yield(n) {
				return
			}
		}
	}
}
