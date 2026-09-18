// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package conntrack

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	observerpb "github.com/cilium/cilium/api/v1/observer"
	relaypb "github.com/cilium/cilium/api/v1/relay"
	"github.com/cilium/cilium/pkg/time"
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

	// Second observation of the very same connection, from node "b": lower
	// packet count, higher byte count, and resolved Source/Service/node name.
	svc := &flowpb.Service{Name: "svc"}
	src := &flowpb.Endpoint{PodName: "client"}
	aggregateCtEntry(entries, &observerpb.ConntrackEntry{
		SourceIp:            "10.0.0.1",
		DestinationIp:       "10.0.0.2",
		DestinationPort:     80,
		Protocol:            6,
		Packets:             10,
		Bytes:               5000,
		Source:              src,
		Service:             svc,
		DestinationNodeName: "node-b",
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
	require.EqualValues(t, 5000, merged.GetBytes())
	require.EqualValues(t, 2, merged.GetCount())
	// Metadata is filled in from whichever entry resolved it first; the
	// second entry's Source/Service are kept since the first had none, but
	// the first entry never had a Destination to begin with.
	require.Same(t, src, merged.Source)
	require.Same(t, svc, merged.Service)
	require.Nil(t, merged.Destination)
	require.Equal(t, "node-b", merged.DestinationNodeName)

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

func TestCTExporter_Cache(t *testing.T) {
	response := []*observerpb.GetConntrackSnapshotResponse{
		{
			ResponseTypes: &observerpb.GetConntrackSnapshotResponse_Entry{
				Entry: &observerpb.ConntrackEntry{SourceIp: "10.0.0.1", DestinationIp: "10.0.0.2", DestinationPort: 80, Protocol: 6, Packets: 5},
			},
		},
	}

	var calls atomic.Int32
	c := newCTExporter(10*time.Second, func(ctx context.Context) ([]*observerpb.GetConntrackSnapshotResponse, error) {
		calls.Add(1)
		return response, nil
	})

	snap, err := c.GetConntrackSnapshot(t.Context())
	require.NoError(t, err)
	require.Len(t, snap.Entries, 1)
	require.Empty(t, snap.NodeStatuses)

	snap2, err := c.GetConntrackSnapshot(t.Context())
	require.NoError(t, err)
	require.Equal(t, snap.ComputedAt, snap2.ComputedAt, "second call within the TTL should reuse the cached snapshot")
	require.EqualValues(t, 1, calls.Load())

	c.cacheTTL = 0

	snap3, err := c.GetConntrackSnapshot(t.Context())
	require.NoError(t, err)
	require.NotEqual(t, snap.ComputedAt, snap3.ComputedAt, "call after the TTL has expired should trigger a refresh")
	require.EqualValues(t, 2, calls.Load())
}

func TestCTExporter_AllPeersFailedNotCached(t *testing.T) {
	response := []*observerpb.GetConntrackSnapshotResponse{
		{
			ResponseTypes: &observerpb.GetConntrackSnapshotResponse_NodeStatus{
				NodeStatus: &relaypb.NodeStatusEvent{StateChange: relaypb.NodeState_NODE_ERROR, NodeNames: []string{"node-a"}},
			},
		},
	}

	var calls atomic.Int32
	c := newCTExporter(10*time.Second, func(ctx context.Context) ([]*observerpb.GetConntrackSnapshotResponse, error) {
		calls.Add(1)
		return response, nil
	})

	snap, err := c.GetConntrackSnapshot(t.Context())
	require.NoError(t, err)
	require.Nil(t, snap.Entries)
	require.Len(t, snap.NodeStatuses, 1)

	// A result where every peer failed must not be cached, so the next call
	// retries immediately instead of sticking on the error for the TTL.
	_, err = c.GetConntrackSnapshot(t.Context())
	require.NoError(t, err)
	require.EqualValues(t, 2, calls.Load())
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
