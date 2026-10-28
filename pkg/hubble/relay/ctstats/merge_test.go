// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package ctstats

import (
	"context"
	"errors"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	conntrackpb "github.com/cilium/cilium/api/v1/conntrack"
	relaypb "github.com/cilium/cilium/api/v1/relay"
)

func TestAggregateGlobalCtEntry(t *testing.T) {
	entries := make(map[ctKey]*ctValue)

	// First observation of the connection, from node "a": higher packet
	// count, no bytes, no resolved metadata.
	aggregateCtEntry(entries, &conntrackpb.Entry{
		Key: &conntrackpb.Key{
			SourceIp:        "10.0.0.1",
			DestinationIp:   "10.0.0.2",
			DestinationPort: 80,
			Protocol:        6,
		},
		Value: &conntrackpb.Value{RxPackets: 20, RxBytes: 0},
	})

	// A distinct connection (different destination port) must not be merged
	// into the one above.
	aggregateCtEntry(entries, &conntrackpb.Entry{
		Key: &conntrackpb.Key{
			SourceIp:        "10.0.0.1",
			DestinationIp:   "10.0.0.2",
			DestinationPort: 443,
			Protocol:        6,
		},
		Value: &conntrackpb.Value{RxPackets: 1, RxBytes: 1},
	})

	require.Len(t, entries, 2)

	merged := entries[ctKey{srcIP: "10.0.0.1", dstIP: "10.0.0.2", dstPort: 80, protocol: 6}]
	require.NotNil(t, merged)
	// Counters are reconciled by keeping the higher of the two independent
	// measurements, not by summing them.
	require.EqualValues(t, 20, merged.RxPackets)
	require.EqualValues(t, 0, merged.RxBytes)

	other := entries[ctKey{srcIP: "10.0.0.1", dstIP: "10.0.0.2", dstPort: 443, protocol: 6}]
	require.NotNil(t, other)
	require.EqualValues(t, 1, other.RxPackets)
	require.EqualValues(t, 1, other.RxBytes)
}

func TestAggregateGlobalCtEntry_SameConnection(t *testing.T) {
	entries := make(map[ctKey]*ctValue)

	key := &conntrackpb.Key{
		SourceIp:        "10.0.0.1",
		DestinationIp:   "10.0.0.2",
		DestinationPort: 80,
		Protocol:        6,
	}

	aggregateCtEntry(entries, &conntrackpb.Entry{
		Key:   key,
		Value: &conntrackpb.Value{RxPackets: 5, RxBytes: 100},
	})

	// The same connection observed from node "b", with a distinct
	// *ConntrackStatsKey instance (as would happen across two peer responses)
	// but the same logical identity: it must be merged, not duplicated.
	aggregateCtEntry(entries, &conntrackpb.Entry{
		Key: &conntrackpb.Key{
			SourceIp:        "10.0.0.1",
			DestinationIp:   "10.0.0.2",
			DestinationPort: 80,
			Protocol:        6,
		},
		Value: &conntrackpb.Value{RxPackets: 10, RxBytes: 50},
	})

	require.Len(t, entries, 1)

	merged := entries[ctKey{srcIP: "10.0.0.1", dstIP: "10.0.0.2", dstPort: 80, protocol: 6}]
	require.NotNil(t, merged)
	require.EqualValues(t, 10, merged.RxPackets)
	require.EqualValues(t, 100, merged.RxBytes)
}

func TestAggregateGlobalCtEntry_InOutMirror(t *testing.T) {
	entries := make(map[ctKey]*ctValue)

	// Sending endpoint's node reports the TUPLE_F_OUT view first.
	aggregateCtEntry(entries, &conntrackpb.Entry{
		Key: &conntrackpb.Key{
			SourceIp:        "10.244.0.6",
			SourcePort:      40924,
			DestinationIp:   "10.244.1.151",
			DestinationPort: 53,
			Protocol:        17,
			Flags:           0, // TUPLE_F_OUT
		},
		Value: &conntrackpb.Value{RxPackets: 1, RxBytes: 205, TxPackets: 1, TxBytes: 112},
	})

	// Receiving endpoint's node reports the TUPLE_F_IN mirror: RX/TX swapped.
	aggregateCtEntry(entries, &conntrackpb.Entry{
		Key: &conntrackpb.Key{
			SourceIp:        "10.244.0.6",
			SourcePort:      40924,
			DestinationIp:   "10.244.1.151",
			DestinationPort: 53,
			Protocol:        17,
			Flags:           1, // TUPLE_F_IN
		},
		Value: &conntrackpb.Value{RxPackets: 1, RxBytes: 112, TxPackets: 1, TxBytes: 205},
	})

	require.Len(t, entries, 1)

	merged := entries[ctKey{srcIP: "10.244.0.6", dstIP: "10.244.1.151", srcPort: 40924, dstPort: 53, protocol: 17}]
	require.NotNil(t, merged)
	require.EqualValues(t, 0, merged.flags)
	require.EqualValues(t, 1, merged.RxPackets)
	require.EqualValues(t, 205, merged.RxBytes)
	require.EqualValues(t, 1, merged.TxPackets)
	require.EqualValues(t, 112, merged.TxBytes)
}

func TestAggregateGlobalCtEntry_InOutMirror_ReverseOrder(t *testing.T) {
	entries := make(map[ctKey]*ctValue)

	aggregateCtEntry(entries, &conntrackpb.Entry{
		Key: &conntrackpb.Key{
			SourceIp:        "10.244.0.6",
			SourcePort:      40924,
			DestinationIp:   "10.244.1.151",
			DestinationPort: 53,
			Protocol:        17,
			Flags:           1, // TUPLE_F_IN
		},
		Value: &conntrackpb.Value{RxPackets: 1, RxBytes: 112, TxPackets: 1, TxBytes: 205},
	})

	aggregateCtEntry(entries, &conntrackpb.Entry{
		Key: &conntrackpb.Key{
			SourceIp:        "10.244.0.6",
			SourcePort:      40924,
			DestinationIp:   "10.244.1.151",
			DestinationPort: 53,
			Protocol:        17,
			Flags:           0, // TUPLE_F_OUT
		},
		Value: &conntrackpb.Value{RxPackets: 1, RxBytes: 205, TxPackets: 1, TxBytes: 112},
	})

	require.Len(t, entries, 1)

	merged := entries[ctKey{srcIP: "10.244.0.6", dstIP: "10.244.1.151", srcPort: 40924, dstPort: 53, protocol: 17}]
	require.NotNil(t, merged)
	require.EqualValues(t, 0, merged.flags)
	require.EqualValues(t, 205, merged.RxBytes)
}

func TestMergeConntrackResponses(t *testing.T) {
	responses := make(chan *conntrackpb.GetStatsResponse, 3)
	responses <- &conntrackpb.GetStatsResponse{
		ResponseTypes: &conntrackpb.GetStatsResponse_Entry{
			Entry: &conntrackpb.Entry{
				Key:   &conntrackpb.Key{SourceIp: "10.0.0.1", DestinationIp: "10.0.0.2", DestinationPort: 80, Protocol: 6},
				Value: &conntrackpb.Value{RxPackets: 5},
			},
		},
	}
	responses <- &conntrackpb.GetStatsResponse{
		ResponseTypes: &conntrackpb.GetStatsResponse_Entry{
			Entry: &conntrackpb.Entry{
				Key:   &conntrackpb.Key{SourceIp: "10.0.0.3", DestinationIp: "10.0.0.4", DestinationPort: 443, Protocol: 6},
				Value: &conntrackpb.Value{RxPackets: 1},
			},
		},
	}
	responses <- &conntrackpb.GetStatsResponse{
		ResponseTypes: &conntrackpb.GetStatsResponse_NodeStatus{
			NodeStatus: &relaypb.NodeStatusEvent{StateChange: relaypb.NodeState_NODE_ERROR, NodeNames: []string{"node-c"}},
		},
	}
	close(responses)

	stats := mergeConntrackResponses(responses)
	require.Len(t, stats.entries, 2)

	require.Len(t, stats.nodeStatuses, 1)
	require.Equal(t, []string{"node-c"}, stats.nodeStatuses[0].GetNodeStatus().GetNodeNames())
}

func TestMergeConntrackResponses_AllPeersFailed(t *testing.T) {
	responses := make(chan *conntrackpb.GetStatsResponse, 1)
	responses <- &conntrackpb.GetStatsResponse{
		ResponseTypes: &conntrackpb.GetStatsResponse_NodeStatus{
			NodeStatus: &relaypb.NodeStatusEvent{StateChange: relaypb.NodeState_NODE_ERROR, NodeNames: []string{"node-a"}},
		},
	}
	close(responses)

	stats := mergeConntrackResponses(responses)
	require.Len(t, stats.entries, 0)
	require.Len(t, stats.nodeStatuses, 1)
	require.Equal(t, []string{"node-a"}, stats.nodeStatuses[0].GetNodeStatus().GetNodeNames())
}

func TestExporterCache(t *testing.T) {
	var fetches atomic.Int32
	fetch := func(ctx context.Context) (<-chan *conntrackpb.GetStatsResponse, func() error) {
		fetches.Add(1)
		ch := make(chan *conntrackpb.GetStatsResponse, 1)
		ch <- &conntrackpb.GetStatsResponse{ResponseTypes: &conntrackpb.GetStatsResponse_Entry{
			Entry: &conntrackpb.Entry{
				Key:   &conntrackpb.Key{SourceIp: "10.0.0.1", DestinationIp: "10.0.0.2"},
				Value: &conntrackpb.Value{RxPackets: 1},
			},
		}}
		close(ch)
		return ch, func() error { return nil }
	}

	e := NewStatsExporter(fetch, time.Hour)
	for range 3 {
		s, err := e.Snapshot(context.Background())
		require.NoError(t, err)
		require.Len(t, slices.Collect(s.Entries()), 1)
	}
	require.EqualValues(t, 1, fetches.Load())

	// An expired cache triggers a new fetch.
	e = NewStatsExporter(fetch, time.Nanosecond)
	for range 2 {
		_, err := e.Snapshot(context.Background())
		require.NoError(t, err)
		time.Sleep(time.Millisecond)
	}
	require.EqualValues(t, 3, fetches.Load())
}

func TestExporterCache_ErrorNotCached(t *testing.T) {
	var fetches atomic.Int32
	fetch := func(ctx context.Context) (<-chan *conntrackpb.GetStatsResponse, func() error) {
		fetches.Add(1)
		ch := make(chan *conntrackpb.GetStatsResponse)
		close(ch)
		return ch, func() error { return errors.New("boom") }
	}

	e := NewStatsExporter(fetch, time.Hour)
	for range 2 {
		_, err := e.Snapshot(context.Background())
		require.Error(t, err)
	}
	require.EqualValues(t, 2, fetches.Load())
}
