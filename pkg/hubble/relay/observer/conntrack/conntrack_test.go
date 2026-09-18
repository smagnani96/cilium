// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package conntrack

import (
	"testing"

	"github.com/stretchr/testify/require"

	observerpb "github.com/cilium/cilium/api/v1/observer"
	relaypb "github.com/cilium/cilium/api/v1/relay"
)

func TestAggregateGlobalCtEntry(t *testing.T) {
	entries := make(map[ctAggregationKey]*observerpb.ConntrackEntry)

	// First observation of the connection, from node "a": higher packet
	// count, no bytes, no resolved metadata.
	aggregateCtEntry(entries, &observerpb.ConntrackEntry{
		SourceIp:        "10.0.0.1",
		DestinationIp:   "10.0.0.2",
		DestinationPort: 80,
		Protocol:        6,
		Packets:         20,
		Bytes:           0,
		Count:           2,
	})

	// A distinct connection (different destination port) must not be merged
	// into the one above.
	aggregateCtEntry(entries, &observerpb.ConntrackEntry{
		SourceIp:        "10.0.0.1",
		DestinationIp:   "10.0.0.2",
		DestinationPort: 443,
		Protocol:        6,
		Packets:         1,
		Bytes:           1,
		Count:           1,
	})

	require.Len(t, entries, 2)

	merged := entries[ctAggregationKey{sourceIP: "10.0.0.1", destinationIP: "10.0.0.2", destinationPort: 80, protocol: 6}]
	require.NotNil(t, merged)
	// Counters are reconciled by keeping the higher of the two independent
	// measurements, not by summing them.
	require.EqualValues(t, 20, merged.GetPackets())
	require.EqualValues(t, 0, merged.GetBytes())
	require.EqualValues(t, 2, merged.GetCount())

	other := entries[ctAggregationKey{sourceIP: "10.0.0.1", destinationIP: "10.0.0.2", destinationPort: 443, protocol: 6}]
	require.NotNil(t, other)
	require.EqualValues(t, 1, other.GetPackets())
	require.EqualValues(t, 1, other.GetBytes())
	require.EqualValues(t, 1, other.GetCount())
}

func TestMergeConntrackResponses(t *testing.T) {
	responses := []*observerpb.GetConntrackSnapshotResponse{
		{
			ResponseTypes: &observerpb.GetConntrackSnapshotResponse_Entry{
				Entry: &observerpb.ConntrackEntry{SourceIp: "10.0.0.1", DestinationIp: "10.0.0.2", DestinationPort: 80, Protocol: 6, Packets: 5},
			},
		},
		{
			ResponseTypes: &observerpb.GetConntrackSnapshotResponse_Entry{
				Entry: &observerpb.ConntrackEntry{SourceIp: "10.0.0.3", DestinationIp: "10.0.0.4", DestinationPort: 443, Protocol: 6, Packets: 1},
			},
		},
		{
			ResponseTypes: &observerpb.GetConntrackSnapshotResponse_NodeStatus{
				NodeStatus: &relaypb.NodeStatusEvent{StateChange: relaypb.NodeState_NODE_ERROR, NodeNames: []string{"node-c"}},
			},
		},
	}

	entries, nodeStatuses := mergeConntrackResponses(responses)
	require.Len(t, entries, 2)

	require.Len(t, nodeStatuses, 1)
	require.Equal(t, []string{"node-c"}, nodeStatuses[0].GetNodeStatus().GetNodeNames())
}

func TestMergeConntrackResponses_AllPeersFailed(t *testing.T) {
	responses := []*observerpb.GetConntrackSnapshotResponse{
		{
			ResponseTypes: &observerpb.GetConntrackSnapshotResponse_NodeStatus{
				NodeStatus: &relaypb.NodeStatusEvent{StateChange: relaypb.NodeState_NODE_ERROR, NodeNames: []string{"node-a"}},
			},
		},
	}

	entries, nodeStatuses := mergeConntrackResponses(responses)
	require.Nil(t, entries)
	require.Len(t, nodeStatuses, 1)
	require.Equal(t, []string{"node-a"}, nodeStatuses[0].GetNodeStatus().GetNodeNames())
}
