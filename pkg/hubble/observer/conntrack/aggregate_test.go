// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package conntrack

import (
	"iter"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	observerpb "github.com/cilium/cilium/api/v1/observer"
)

func TestAggregate_NoGroupByIsPassthrough(t *testing.T) {
	stats := &ctStats{entries: make(map[mergeKey]*ctEntry)}
	got := Aggregate(stats, nil)
	require.Same(t, Snapshot(stats), got)
}

func newTestEntry(srcIP string, srcPort uint32, dstIP string, dstPort uint32, rxPackets, txPackets uint64) *observerpb.ConntrackStatsEntry {
	return &observerpb.ConntrackStatsEntry{
		Key: &observerpb.ConntrackStatsKey{
			SourceIp:        srcIP,
			SourcePort:      srcPort,
			DestinationIp:   dstIP,
			DestinationPort: dstPort,
			Protocol:        6,
		},
		Value: &observerpb.ConntrackStatsValue{
			RxPackets: rxPackets,
			TxPackets: txPackets,
		},
		Count: 1,
	}
}

// fakeSnapshot is a Snapshot backed by fixed slices, for exercising
// Aggregate independently of ctStats.
type fakeSnapshot struct {
	entries   []*observerpb.ConntrackStatsEntry
	endpoints []*observerpb.ConntrackStatsEndpoint
	nodes     []*observerpb.ConntrackStatsNode
}

func (f *fakeSnapshot) Entries() iter.Seq[*observerpb.ConntrackStatsEntry] {
	return func(yield func(*observerpb.ConntrackStatsEntry) bool) {
		for _, e := range f.entries {
			if !yield(e) {
				return
			}
		}
	}
}

func (f *fakeSnapshot) Endpoints() iter.Seq[*observerpb.ConntrackStatsEndpoint] {
	return func(yield func(*observerpb.ConntrackStatsEndpoint) bool) {
		for _, ep := range f.endpoints {
			if !yield(ep) {
				return
			}
		}
	}
}

func (f *fakeSnapshot) Nodes() iter.Seq[*observerpb.ConntrackStatsNode] {
	return func(yield func(*observerpb.ConntrackStatsNode) bool) {
		for _, n := range f.nodes {
			if !yield(n) {
				return
			}
		}
	}
}

// TestAggregate_GroupBySourceIP verifies that entries sharing a source IP
// are folded into a single entry with summed counters, and every other
// field cleared, regardless of how many distinct destinations they had.
func TestAggregate_GroupBySourceIP(t *testing.T) {
	snap := &fakeSnapshot{entries: []*observerpb.ConntrackStatsEntry{
		newTestEntry("10.0.0.1", 1000, "10.0.0.2", 80, 3, 4),
		newTestEntry("10.0.0.1", 2000, "10.0.0.3", 443, 5, 6),
		newTestEntry("10.0.0.9", 3000, "10.0.0.2", 80, 100, 200),
	}}

	got := Aggregate(snap, []observerpb.ConntrackAggregationField{
		observerpb.ConntrackAggregationField_CONNTRACK_AGGREGATION_FIELD_SOURCE_IP,
	})

	var entries []*observerpb.ConntrackStatsEntry
	for e := range got.Entries() {
		entries = append(entries, e)
	}
	require.Len(t, entries, 2)

	byIP := make(map[string]*observerpb.ConntrackStatsEntry, 2)
	for _, e := range entries {
		byIP[e.GetKey().GetSourceIp()] = e
	}

	merged := byIP["10.0.0.1"]
	require.NotNil(t, merged)
	require.Equal(t, uint64(8), merged.GetValue().GetRxPackets())
	require.Equal(t, uint64(10), merged.GetValue().GetTxPackets())
	require.Equal(t, uint64(2), merged.GetCount())
	require.Empty(t, merged.GetKey().GetDestinationIp())
	require.Zero(t, merged.GetKey().GetSourcePort())
	require.Zero(t, merged.GetKey().GetProtocol())

	untouched := byIP["10.0.0.9"]
	require.NotNil(t, untouched)
	require.Equal(t, uint64(100), untouched.GetValue().GetRxPackets())
	require.Equal(t, uint64(1), untouched.GetCount())
}

// TestAggregate_GroupBySourceIPPreservesEndpoint verifies that grouping by
// the raw SOURCE_IP still carries over the resolved source Endpoint, even
// though SOURCE_ENDPOINT wasn't itself requested: every entry folded into a
// SOURCE_IP group necessarily shares the same source IP, and endpoint
// resolution is a pure function of that IP, so it's unambiguous.
func TestAggregate_GroupBySourceIPPreservesEndpoint(t *testing.T) {
	client := &flowpb.Endpoint{ID: 7, Namespace: "default", PodName: "client"}

	e1 := newTestEntry("10.0.0.1", 1000, "10.0.0.9", 80, 1, 1)
	e1.SourceEndpointIndex = Wrap(uintPtr(0))
	e2 := newTestEntry("10.0.0.1", 2000, "10.0.0.10", 443, 2, 2)
	e2.SourceEndpointIndex = Wrap(uintPtr(0))

	snap := &fakeSnapshot{
		entries:   []*observerpb.ConntrackStatsEntry{e1, e2},
		endpoints: []*observerpb.ConntrackStatsEndpoint{{Index: 0, Endpoint: client}},
	}

	got := Aggregate(snap, []observerpb.ConntrackAggregationField{
		observerpb.ConntrackAggregationField_CONNTRACK_AGGREGATION_FIELD_SOURCE_IP,
	})

	var entries []*observerpb.ConntrackStatsEntry
	for e := range got.Entries() {
		entries = append(entries, e)
	}
	require.Len(t, entries, 1)
	require.NotNil(t, entries[0].GetSourceEndpointIndex())

	var endpoints []*observerpb.ConntrackStatsEndpoint
	for ep := range got.Endpoints() {
		endpoints = append(endpoints, ep)
	}
	require.Len(t, endpoints, 1)
	require.True(t, proto.Equal(client, endpoints[0].GetEndpoint()))
	require.Equal(t, endpoints[0].GetIndex(), entries[0].GetSourceEndpointIndex().GetValue())
}

// TestAggregate_GroupByDestinationPortDropsEndpoint verifies that grouping
// by a field unrelated to the source/destination IP (here, only
// DESTINATION_PORT) does *not* carry over any Endpoint/node, since a group
// can then mix entries with different, unrelated sources/destinations.
func TestAggregate_GroupByDestinationPortDropsEndpoint(t *testing.T) {
	client := &flowpb.Endpoint{ID: 7, Namespace: "default", PodName: "client"}

	e1 := newTestEntry("10.0.0.1", 1000, "10.0.0.9", 80, 1, 1)
	e1.SourceEndpointIndex = Wrap(uintPtr(0))
	e2 := newTestEntry("10.0.0.2", 2000, "10.0.0.10", 80, 2, 2)

	snap := &fakeSnapshot{
		entries:   []*observerpb.ConntrackStatsEntry{e1, e2},
		endpoints: []*observerpb.ConntrackStatsEndpoint{{Index: 0, Endpoint: client}},
	}

	got := Aggregate(snap, []observerpb.ConntrackAggregationField{
		observerpb.ConntrackAggregationField_CONNTRACK_AGGREGATION_FIELD_DESTINATION_PORT,
	})

	var entries []*observerpb.ConntrackStatsEntry
	for e := range got.Entries() {
		entries = append(entries, e)
	}
	require.Len(t, entries, 1)
	require.Nil(t, entries[0].GetSourceEndpointIndex())

	for range got.Endpoints() {
		t.Fatal("expected no endpoints to be carried over")
	}
}

// TestAggregate_GroupBySourceEndpointCollapsesChurnedEndpointID verifies
// that two ConntrackStatsEndpoint values for the same pod (same
// namespace/pod_name, e.g. observed before and after its Cilium endpoint
// was regenerated with a different id, or its identity churned) are folded
// into a single group by SOURCE_ENDPOINT, rather than reported as two
// distinct pods just because their EndpointDedup identity differs.
func TestAggregate_GroupBySourceEndpointCollapsesChurnedEndpointID(t *testing.T) {
	beforeRegen := &flowpb.Endpoint{Identity: 30003, Namespace: "cilium-test-1", PodName: "client-657b75749d-q444l", PodUid: "ffa86fd4-0386-422c-baeb-6e82b9985e78"}
	afterRegen := &flowpb.Endpoint{ID: 576, Identity: 30003, Namespace: "cilium-test-1", PodName: "client-657b75749d-q444l", PodUid: "ffa86fd4-0386-422c-baeb-6e82b9985e78"}

	e1 := newTestEntry("10.0.0.1", 1000, "10.0.0.9", 80, 25, 25)
	e1.SourceEndpointIndex = Wrap(uintPtr(0))
	e2 := newTestEntry("10.0.0.1", 2000, "10.0.0.10", 443, 5, 5)
	e2.SourceEndpointIndex = Wrap(uintPtr(1))

	snap := &fakeSnapshot{
		entries: []*observerpb.ConntrackStatsEntry{e1, e2},
		endpoints: []*observerpb.ConntrackStatsEndpoint{
			{Index: 0, Endpoint: beforeRegen},
			{Index: 1, Endpoint: afterRegen},
		},
	}

	got := Aggregate(snap, []observerpb.ConntrackAggregationField{
		observerpb.ConntrackAggregationField_CONNTRACK_AGGREGATION_FIELD_SOURCE_ENDPOINT,
	})

	var entries []*observerpb.ConntrackStatsEntry
	for e := range got.Entries() {
		entries = append(entries, e)
	}
	require.Len(t, entries, 1)
	require.Equal(t, uint64(30), entries[0].GetValue().GetRxPackets())

	var endpoints []*observerpb.ConntrackStatsEndpoint
	for ep := range got.Endpoints() {
		endpoints = append(endpoints, ep)
	}
	require.Len(t, endpoints, 1)
}

// TestAggregate_GroupBySourceEndpoint verifies that grouping by the resolved
// source Endpoint (instead of the raw source IP) folds entries from a
// multi-IP endpoint into one, and that unresolved entries land in their own,
// shared group instead of being dropped.
func TestAggregate_GroupBySourceEndpoint(t *testing.T) {
	server := &flowpb.Endpoint{ID: 42, Namespace: "default", PodName: "server"}

	e1 := newTestEntry("10.0.0.1", 1000, "10.0.0.9", 80, 1, 1)
	e1.SourceEndpointIndex = Wrap(uintPtr(0))
	e2 := newTestEntry("10.0.0.2", 2000, "10.0.0.9", 443, 2, 2)
	e2.SourceEndpointIndex = Wrap(uintPtr(0))
	unresolved := newTestEntry("10.0.0.3", 3000, "10.0.0.9", 53, 5, 5)

	snap := &fakeSnapshot{
		entries:   []*observerpb.ConntrackStatsEntry{e1, e2, unresolved},
		endpoints: []*observerpb.ConntrackStatsEndpoint{{Index: 0, Endpoint: server}},
	}

	got := Aggregate(snap, []observerpb.ConntrackAggregationField{
		observerpb.ConntrackAggregationField_CONNTRACK_AGGREGATION_FIELD_SOURCE_ENDPOINT,
	})

	var entries []*observerpb.ConntrackStatsEntry
	for e := range got.Entries() {
		entries = append(entries, e)
	}
	require.Len(t, entries, 2)

	var endpoints []*observerpb.ConntrackStatsEndpoint
	for ep := range got.Endpoints() {
		endpoints = append(endpoints, ep)
	}
	require.Len(t, endpoints, 1)
	require.True(t, proto.Equal(server, endpoints[0].GetEndpoint()))

	var resolved, unresolvedEntry *observerpb.ConntrackStatsEntry
	for _, e := range entries {
		if e.GetSourceEndpointIndex() != nil {
			resolved = e
		} else {
			unresolvedEntry = e
		}
	}
	require.NotNil(t, resolved)
	require.Equal(t, uint64(3), resolved.GetValue().GetRxPackets())
	require.Equal(t, endpoints[0].GetIndex(), resolved.GetSourceEndpointIndex().GetValue())

	require.NotNil(t, unresolvedEntry)
	require.Equal(t, uint64(5), unresolvedEntry.GetValue().GetRxPackets())
}

func uintPtr(v uint32) *uint32 { return &v }
