// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package conntrack

import (
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	observerpb "github.com/cilium/cilium/api/v1/observer"
	relaypb "github.com/cilium/cilium/api/v1/relay"
	hubbleconntrack "github.com/cilium/cilium/pkg/hubble/observer/conntrack"
)

func TestAggregateGlobalCtEntry(t *testing.T) {
	entries := make(map[ctKey]*ctValue)
	dedup := hubbleconntrack.NewEndpointDedup()

	// First observation of the connection, from node "a": higher packet
	// count, no bytes, no resolved metadata.
	aggregateCtEntry(entries, &observerpb.ConntrackStatsEntry{
		Key: &observerpb.ConntrackStatsKey{
			SourceIp:        "10.0.0.1",
			DestinationIp:   "10.0.0.2",
			DestinationPort: 80,
			Protocol:        6,
		},
		Value: &observerpb.ConntrackStatsValue{RxPackets: 20, RxBytes: 0},
	}, nil, nil, dedup)

	// A distinct connection (different destination port) must not be merged
	// into the one above.
	aggregateCtEntry(entries, &observerpb.ConntrackStatsEntry{
		Key: &observerpb.ConntrackStatsKey{
			SourceIp:        "10.0.0.1",
			DestinationIp:   "10.0.0.2",
			DestinationPort: 443,
			Protocol:        6,
		},
		Value: &observerpb.ConntrackStatsValue{RxPackets: 1, RxBytes: 1},
	}, nil, nil, dedup)

	require.Len(t, entries, 2)

	merged := entries[ctKey{srcIP: "10.0.0.1", dstIP: "10.0.0.2", dstPort: 80, protocol: 6}]
	require.NotNil(t, merged)
	// Counters are reconciled by keeping the higher of the two independent
	// measurements, not by summing them.
	require.EqualValues(t, 20, merged.rxPackets)
	require.EqualValues(t, 0, merged.rxBytes)

	other := entries[ctKey{srcIP: "10.0.0.1", dstIP: "10.0.0.2", dstPort: 443, protocol: 6}]
	require.NotNil(t, other)
	require.EqualValues(t, 1, other.rxPackets)
	require.EqualValues(t, 1, other.rxBytes)
}

func TestAggregateGlobalCtEntry_SameConnection(t *testing.T) {
	entries := make(map[ctKey]*ctValue)
	dedup := hubbleconntrack.NewEndpointDedup()

	key := &observerpb.ConntrackStatsKey{
		SourceIp:        "10.0.0.1",
		DestinationIp:   "10.0.0.2",
		DestinationPort: 80,
		Protocol:        6,
	}

	// Observed from node "a".
	aggregateCtEntry(entries, &observerpb.ConntrackStatsEntry{
		Key:   key,
		Value: &observerpb.ConntrackStatsValue{RxPackets: 5, RxBytes: 100},
	}, nil, nil, dedup)

	// The same connection observed from node "b", with a distinct
	// *ConntrackStatsKey instance (as would happen across two peer responses)
	// but the same logical identity: it must be merged, not duplicated.
	aggregateCtEntry(entries, &observerpb.ConntrackStatsEntry{
		Key: &observerpb.ConntrackStatsKey{
			SourceIp:        "10.0.0.1",
			DestinationIp:   "10.0.0.2",
			DestinationPort: 80,
			Protocol:        6,
		},
		Value: &observerpb.ConntrackStatsValue{RxPackets: 10, RxBytes: 50},
	}, nil, nil, dedup)

	require.Len(t, entries, 1)

	merged := entries[ctKey{srcIP: "10.0.0.1", dstIP: "10.0.0.2", dstPort: 80, protocol: 6}]
	require.NotNil(t, merged)
	require.EqualValues(t, 10, merged.rxPackets)
	require.EqualValues(t, 100, merged.rxBytes)
}

// TestAggregateGlobalCtEntry_InOutMirror verifies that a TUPLE_F_OUT entry
// reported by the sending endpoint's node and its TUPLE_F_IN mirror reported
// by the receiving endpoint's node (RX/TX swapped, same physical traffic)
// are collapsed into a single connection using the canonical (TUPLE_F_OUT)
// counters, instead of being kept as two rows or merged/maxed together.
func TestAggregateGlobalCtEntry_InOutMirror(t *testing.T) {
	entries := make(map[ctKey]*ctValue)
	dedup := hubbleconntrack.NewEndpointDedup()

	// Sending endpoint's node reports the TUPLE_F_OUT view first.
	aggregateCtEntry(entries, &observerpb.ConntrackStatsEntry{
		Key: &observerpb.ConntrackStatsKey{
			SourceIp:        "10.244.0.6",
			SourcePort:      40924,
			DestinationIp:   "10.244.1.151",
			DestinationPort: 53,
			Protocol:        17,
			Flags:           0, // TUPLE_F_OUT
		},
		Value: &observerpb.ConntrackStatsValue{RxPackets: 1, RxBytes: 205, TxPackets: 1, TxBytes: 112},
	}, nil, nil, dedup)

	// Receiving endpoint's node reports the TUPLE_F_IN mirror: RX/TX swapped.
	aggregateCtEntry(entries, &observerpb.ConntrackStatsEntry{
		Key: &observerpb.ConntrackStatsKey{
			SourceIp:        "10.244.0.6",
			SourcePort:      40924,
			DestinationIp:   "10.244.1.151",
			DestinationPort: 53,
			Protocol:        17,
			Flags:           1, // TUPLE_F_IN
		},
		Value: &observerpb.ConntrackStatsValue{RxPackets: 1, RxBytes: 112, TxPackets: 1, TxBytes: 205},
	}, nil, nil, dedup)

	require.Len(t, entries, 1)

	merged := entries[ctKey{srcIP: "10.244.0.6", dstIP: "10.244.1.151", srcPort: 40924, dstPort: 53, protocol: 17}]
	require.NotNil(t, merged)
	require.EqualValues(t, 0, merged.flags)
	require.EqualValues(t, 1, merged.rxPackets)
	require.EqualValues(t, 205, merged.rxBytes)
	require.EqualValues(t, 1, merged.txPackets)
	require.EqualValues(t, 112, merged.txBytes)
}

// TestAggregateGlobalCtEntry_InOutMirror_ReverseOrder verifies the merge is
// order-independent: the canonical TUPLE_F_OUT entry wins even if its
// TUPLE_F_IN mirror is reported first.
func TestAggregateGlobalCtEntry_InOutMirror_ReverseOrder(t *testing.T) {
	entries := make(map[ctKey]*ctValue)
	dedup := hubbleconntrack.NewEndpointDedup()

	aggregateCtEntry(entries, &observerpb.ConntrackStatsEntry{
		Key: &observerpb.ConntrackStatsKey{
			SourceIp:        "10.244.0.6",
			SourcePort:      40924,
			DestinationIp:   "10.244.1.151",
			DestinationPort: 53,
			Protocol:        17,
			Flags:           1, // TUPLE_F_IN
		},
		Value: &observerpb.ConntrackStatsValue{RxPackets: 1, RxBytes: 112, TxPackets: 1, TxBytes: 205},
	}, nil, nil, dedup)

	aggregateCtEntry(entries, &observerpb.ConntrackStatsEntry{
		Key: &observerpb.ConntrackStatsKey{
			SourceIp:        "10.244.0.6",
			SourcePort:      40924,
			DestinationIp:   "10.244.1.151",
			DestinationPort: 53,
			Protocol:        17,
			Flags:           0, // TUPLE_F_OUT
		},
		Value: &observerpb.ConntrackStatsValue{RxPackets: 1, RxBytes: 205, TxPackets: 1, TxBytes: 112},
	}, nil, nil, dedup)

	require.Len(t, entries, 1)

	merged := entries[ctKey{srcIP: "10.244.0.6", dstIP: "10.244.1.151", srcPort: 40924, dstPort: 53, protocol: 17}]
	require.NotNil(t, merged)
	require.EqualValues(t, 0, merged.flags)
	require.EqualValues(t, 205, merged.rxBytes)
}

func TestMergeConntrackResponses(t *testing.T) {
	responses := make(chan *PeerResponse, 3)
	responses <- &PeerResponse{Peer: "node-a", Response: &observerpb.GetConntrackStatsResponse{
		ResponseTypes: &observerpb.GetConntrackStatsResponse_Entry{
			Entry: &observerpb.ConntrackStatsEntry{
				Key:   &observerpb.ConntrackStatsKey{SourceIp: "10.0.0.1", DestinationIp: "10.0.0.2", DestinationPort: 80, Protocol: 6},
				Value: &observerpb.ConntrackStatsValue{RxPackets: 5},
			},
		},
	}}
	responses <- &PeerResponse{Peer: "node-b", Response: &observerpb.GetConntrackStatsResponse{
		ResponseTypes: &observerpb.GetConntrackStatsResponse_Entry{
			Entry: &observerpb.ConntrackStatsEntry{
				Key:   &observerpb.ConntrackStatsKey{SourceIp: "10.0.0.3", DestinationIp: "10.0.0.4", DestinationPort: 443, Protocol: 6},
				Value: &observerpb.ConntrackStatsValue{RxPackets: 1},
			},
		},
	}}
	responses <- &PeerResponse{Peer: "node-c", Response: &observerpb.GetConntrackStatsResponse{
		ResponseTypes: &observerpb.GetConntrackStatsResponse_NodeStatus{
			NodeStatus: &relaypb.NodeStatusEvent{StateChange: relaypb.NodeState_NODE_ERROR, NodeNames: []string{"node-c"}},
		},
	}}
	close(responses)

	stats := mergeConntrackResponses(responses)
	require.Len(t, stats.entries, 2)
	require.Empty(t, stats.endpoints.List())

	require.Len(t, stats.nodeStatuses, 1)
	require.Equal(t, []string{"node-c"}, stats.nodeStatuses[0].GetNodeStatus().GetNodeNames())
}

func TestMergeConntrackResponses_AllPeersFailed(t *testing.T) {
	responses := make(chan *PeerResponse, 1)
	responses <- &PeerResponse{Peer: "node-a", Response: &observerpb.GetConntrackStatsResponse{
		ResponseTypes: &observerpb.GetConntrackStatsResponse_NodeStatus{
			NodeStatus: &relaypb.NodeStatusEvent{StateChange: relaypb.NodeState_NODE_ERROR, NodeNames: []string{"node-a"}},
		},
	}}
	close(responses)

	stats := mergeConntrackResponses(responses)
	require.Empty(t, stats.entries)
	require.Len(t, stats.nodeStatuses, 1)
	require.Equal(t, []string{"node-a"}, stats.nodeStatuses[0].GetNodeStatus().GetNodeNames())
}

func TestMergeConntrackResponses_DedupsEndpointsAcrossPeers(t *testing.T) {
	server := &flowpb.Endpoint{ID: 42, Namespace: "default", PodName: "server"}

	responses := make(chan *PeerResponse, 4)
	// node-a resolved the shared destination as its own local index 0.
	responses <- &PeerResponse{Peer: "node-a", Response: &observerpb.GetConntrackStatsResponse{
		ResponseTypes: &observerpb.GetConntrackStatsResponse_Endpoint{
			Endpoint: &observerpb.ConntrackStatsEndpoint{Index: 0, Endpoint: server},
		},
	}}
	responses <- &PeerResponse{Peer: "node-a", Response: &observerpb.GetConntrackStatsResponse{
		ResponseTypes: &observerpb.GetConntrackStatsResponse_Entry{
			Entry: &observerpb.ConntrackStatsEntry{
				Key:                      &observerpb.ConntrackStatsKey{SourceIp: "10.0.0.1", DestinationIp: "10.0.0.2", DestinationPort: 80, Protocol: 6},
				Value:                    &observerpb.ConntrackStatsValue{RxPackets: 5},
				DestinationEndpointIndex: wrapperspb.UInt32(0),
			},
		},
	}}
	// node-b independently resolved the very same pod, but under its own
	// local index 0 too (peer-local index spaces are independent).
	responses <- &PeerResponse{Peer: "node-b", Response: &observerpb.GetConntrackStatsResponse{
		ResponseTypes: &observerpb.GetConntrackStatsResponse_Endpoint{
			Endpoint: &observerpb.ConntrackStatsEndpoint{Index: 0, Endpoint: server},
		},
	}}
	responses <- &PeerResponse{Peer: "node-b", Response: &observerpb.GetConntrackStatsResponse{
		ResponseTypes: &observerpb.GetConntrackStatsResponse_Entry{
			Entry: &observerpb.ConntrackStatsEntry{
				Key:                      &observerpb.ConntrackStatsKey{SourceIp: "10.0.0.3", DestinationIp: "10.0.0.2", DestinationPort: 80, Protocol: 6},
				Value:                    &observerpb.ConntrackStatsValue{RxPackets: 1},
				DestinationEndpointIndex: wrapperspb.UInt32(0),
			},
		},
	}}
	close(responses)

	stats := mergeConntrackResponses(responses)
	require.Len(t, stats.entries, 2)
	require.Empty(t, stats.nodeStatuses)

	// Only one ConntrackStatsEndpoint should have been kept, despite two peers
	// each reporting the shared destination under their own local index.
	got := stats.endpoints.List()
	require.Len(t, got, 1)
	require.True(t, proto.Equal(server, got[0]))

	for _, v := range stats.entries {
		require.NotNil(t, v.dstEndpointIdx)
		require.EqualValues(t, 0, *v.dstEndpointIdx)
	}
}
