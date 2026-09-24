// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package conntrack

import (
	"testing"

	"github.com/stretchr/testify/require"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	observerpb "github.com/cilium/cilium/api/v1/observer"
)

func TestFilter_NilOrEmptyIsPassthrough(t *testing.T) {
	snap := &fakeSnapshot{entries: []*observerpb.ConntrackStatsEntry{newTestEntry("10.0.0.1", 1000, "10.0.0.2", 80, 1, 1)}}
	require.Same(t, Snapshot(snap), Filter(snap, nil))
	require.Same(t, Snapshot(snap), Filter(snap, &observerpb.ConntrackFilter{}))
}

func TestFilter_SourceIP(t *testing.T) {
	snap := &fakeSnapshot{entries: []*observerpb.ConntrackStatsEntry{
		newTestEntry("10.0.0.1", 1000, "10.0.0.9", 80, 1, 1),
		newTestEntry("10.0.0.2", 2000, "10.0.0.9", 80, 2, 2),
	}}

	got := Filter(snap, &observerpb.ConntrackFilter{SourceIp: []string{"10.0.0.1"}})

	var entries []*observerpb.ConntrackStatsEntry
	for e := range got.Entries() {
		entries = append(entries, e)
	}
	require.Len(t, entries, 1)
	require.Equal(t, "10.0.0.1", entries[0].GetKey().GetSourceIp())
}

func TestFilter_SourceIPCIDR(t *testing.T) {
	snap := &fakeSnapshot{entries: []*observerpb.ConntrackStatsEntry{
		newTestEntry("10.0.0.1", 1000, "10.0.0.9", 80, 1, 1),
		newTestEntry("10.1.0.1", 2000, "10.0.0.9", 80, 2, 2),
	}}

	got := Filter(snap, &observerpb.ConntrackFilter{SourceIp: []string{"10.0.0.0/24"}})

	var entries []*observerpb.ConntrackStatsEntry
	for e := range got.Entries() {
		entries = append(entries, e)
	}
	require.Len(t, entries, 1)
	require.Equal(t, "10.0.0.1", entries[0].GetKey().GetSourceIp())
}

func TestFilter_DestinationPort(t *testing.T) {
	snap := &fakeSnapshot{entries: []*observerpb.ConntrackStatsEntry{
		newTestEntry("10.0.0.1", 1000, "10.0.0.9", 80, 1, 1),
		newTestEntry("10.0.0.1", 1000, "10.0.0.9", 443, 2, 2),
	}}

	got := Filter(snap, &observerpb.ConntrackFilter{DestinationPort: []uint32{443}})

	var entries []*observerpb.ConntrackStatsEntry
	for e := range got.Entries() {
		entries = append(entries, e)
	}
	require.Len(t, entries, 1)
	require.EqualValues(t, 443, entries[0].GetKey().GetDestinationPort())
}

// TestFilter_SourceEndpoint verifies that filtering on the resolved source
// Endpoint's namespace/name drops non-matching entries (including
// unresolved ones), and narrows the returned Endpoints/Nodes down to only
// what's still referenced.
func TestFilter_SourceEndpoint(t *testing.T) {
	server := &flowpb.Endpoint{ID: 42, Namespace: "default", PodName: "server"}
	other := &flowpb.Endpoint{ID: 43, Namespace: "kube-system", PodName: "coredns"}

	matching := newTestEntry("10.0.0.1", 1000, "10.0.0.9", 80, 1, 1)
	matching.SourceEndpointIndex = Wrap(uintPtr(0))
	nonMatching := newTestEntry("10.0.0.2", 2000, "10.0.0.9", 80, 2, 2)
	nonMatching.SourceEndpointIndex = Wrap(uintPtr(1))
	unresolved := newTestEntry("10.0.0.3", 3000, "10.0.0.9", 80, 3, 3)

	snap := &fakeSnapshot{
		entries: []*observerpb.ConntrackStatsEntry{matching, nonMatching, unresolved},
		endpoints: []*observerpb.ConntrackStatsEndpoint{
			{Index: 0, Endpoint: server},
			{Index: 1, Endpoint: other},
		},
	}

	got := Filter(snap, &observerpb.ConntrackFilter{SourceEndpoint: []string{"default/server"}})

	var entries []*observerpb.ConntrackStatsEntry
	for e := range got.Entries() {
		entries = append(entries, e)
	}
	require.Len(t, entries, 1)
	require.Equal(t, "10.0.0.1", entries[0].GetKey().GetSourceIp())

	var endpoints []*observerpb.ConntrackStatsEndpoint
	for ep := range got.Endpoints() {
		endpoints = append(endpoints, ep)
	}
	require.Len(t, endpoints, 1)
	require.Equal(t, uint32(0), endpoints[0].GetIndex())
}

func TestFilter_SourceNode(t *testing.T) {
	matching := newTestEntry("10.0.0.1", 1000, "10.0.0.9", 80, 1, 1)
	matching.SourceNodeIndex = Wrap(uintPtr(0))
	nonMatching := newTestEntry("10.0.0.2", 2000, "10.0.0.9", 80, 2, 2)
	nonMatching.SourceNodeIndex = Wrap(uintPtr(1))

	snap := &fakeSnapshot{
		entries: []*observerpb.ConntrackStatsEntry{matching, nonMatching},
		nodes: []*observerpb.ConntrackStatsNode{
			{Index: 0, Name: "node-a"},
			{Index: 1, Name: "node-b"},
		},
	}

	got := Filter(snap, &observerpb.ConntrackFilter{SourceNode: []string{"node-a"}})

	var entries []*observerpb.ConntrackStatsEntry
	for e := range got.Entries() {
		entries = append(entries, e)
	}
	require.Len(t, entries, 1)
	require.Equal(t, "10.0.0.1", entries[0].GetKey().GetSourceIp())

	var nodes []*observerpb.ConntrackStatsNode
	for n := range got.Nodes() {
		nodes = append(nodes, n)
	}
	require.Len(t, nodes, 1)
	require.Equal(t, "node-a", nodes[0].GetName())
}
