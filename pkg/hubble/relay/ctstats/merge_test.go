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
	flowpb "github.com/cilium/cilium/api/v1/flow"
	relaypb "github.com/cilium/cilium/api/v1/relay"
	"github.com/cilium/cilium/pkg/ctstats"
	hubblectstats "github.com/cilium/cilium/pkg/hubble/ctstats"
)

func aggregate(entries map[ctKey]*ctValue, e *conntrackpb.Entry) {
	aggregateCtEntry(entries, e, resolved{}, hubblectstats.NewEndpointDedup(), hubblectstats.NewServiceDedup())
}

func TestAggregateGlobalCtEntry(t *testing.T) {
	entries := make(map[ctKey]*ctValue)

	// First observation of the connection, from node "a": higher packet
	// count, no bytes, no resolved metadata.
	aggregate(entries, &conntrackpb.Entry{
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
	aggregate(entries, &conntrackpb.Entry{
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

	aggregate(entries, &conntrackpb.Entry{
		Key:   key,
		Value: &conntrackpb.Value{RxPackets: 5, RxBytes: 100},
	})

	// The same connection observed from node "b", with a distinct
	// *ConntrackStatsKey instance (as would happen across two peer responses)
	// but the same logical identity: it must be merged, not duplicated.
	aggregate(entries, &conntrackpb.Entry{
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
	aggregate(entries, &conntrackpb.Entry{
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
	aggregate(entries, &conntrackpb.Entry{
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

	aggregate(entries, &conntrackpb.Entry{
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

	aggregate(entries, &conntrackpb.Entry{
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

func peerResp(peer string, resp *conntrackpb.GetStatsResponse) *PeerResponse {
	return &PeerResponse{Peer: peer, Response: resp}
}

func entryResp(e *conntrackpb.Entry) *conntrackpb.GetStatsResponse {
	return &conntrackpb.GetStatsResponse{ResponseTypes: &conntrackpb.GetStatsResponse_Entry{Entry: e}}
}

func endpointResp(idx uint32, ep *flowpb.Endpoint) *conntrackpb.GetStatsResponse {
	return &conntrackpb.GetStatsResponse{ResponseTypes: &conntrackpb.GetStatsResponse_Endpoint{
		Endpoint: &conntrackpb.IndexedEndpoint{Index: idx, Endpoint: ep},
	}}
}

func serviceResp(idx uint32, svc *flowpb.Service) *conntrackpb.GetStatsResponse {
	return &conntrackpb.GetStatsResponse{ResponseTypes: &conntrackpb.GetStatsResponse_Service{
		Service: &conntrackpb.IndexedService{Index: idx, Service: svc},
	}}
}

func nodeErrorResp(node string) *conntrackpb.GetStatsResponse {
	return &conntrackpb.GetStatsResponse{
		ResponseTypes: &conntrackpb.GetStatsResponse_NodeStatus{
			NodeStatus: &relaypb.NodeStatusEvent{StateChange: relaypb.NodeState_NODE_ERROR, NodeNames: []string{node}},
		},
	}
}

func TestMergeConntrackResponses(t *testing.T) {
	responses := make(chan *PeerResponse, 3)
	responses <- peerResp("node-a", entryResp(&conntrackpb.Entry{
		Key:   &conntrackpb.Key{SourceIp: "10.0.0.1", DestinationIp: "10.0.0.2", DestinationPort: 80, Protocol: 6},
		Value: &conntrackpb.Value{RxPackets: 5},
	}))
	responses <- peerResp("node-b", entryResp(&conntrackpb.Entry{
		Key:   &conntrackpb.Key{SourceIp: "10.0.0.3", DestinationIp: "10.0.0.4", DestinationPort: 443, Protocol: 6},
		Value: &conntrackpb.Value{RxPackets: 1},
	}))
	responses <- peerResp("node-c", nodeErrorResp("node-c"))
	close(responses)

	snap := mergeConntrackResponses(responses)
	require.Len(t, snap.entries, 2)
	require.Empty(t, slices.Collect(snap.Endpoints()))

	require.Len(t, snap.nodeStatuses, 1)
	require.Equal(t, []string{"node-c"}, snap.nodeStatuses[0].GetNodeStatus().GetNodeNames())
}

func TestMergeConntrackResponses_AllPeersFailed(t *testing.T) {
	responses := make(chan *PeerResponse, 1)
	responses <- peerResp("node-a", nodeErrorResp("node-a"))
	close(responses)

	snap := mergeConntrackResponses(responses)
	require.Empty(t, snap.entries)
	require.Len(t, snap.nodeStatuses, 1)
	require.Equal(t, []string{"node-a"}, snap.nodeStatuses[0].GetNodeStatus().GetNodeNames())
}

func TestMergeConntrackResponses_Endpoints(t *testing.T) {
	db := &flowpb.Endpoint{Namespace: "default", PodName: "db", PodUid: "db-uid"}
	// Same pod as web, as seen from another node: the endpoint ID is unknown.
	webRemote := &flowpb.Endpoint{Namespace: "default", PodName: "web", PodUid: "web-uid", Identity: 7}
	webLocal := &flowpb.Endpoint{ID: 42, Namespace: "default", PodName: "web", PodUid: "web-uid"}

	key := func(src, dst string) *conntrackpb.Key {
		return &conntrackpb.Key{SourceIp: src, DestinationIp: dst, DestinationPort: 80, Protocol: 6}
	}
	idx := func(i uint32) *uint32 { return &i }

	responses := make(chan *PeerResponse, 16)
	// node-a: web is index 0, db is index 1.
	responses <- peerResp("node-a", endpointResp(0, webLocal))
	responses <- peerResp("node-a", endpointResp(1, db))
	responses <- peerResp("node-a", entryResp(&conntrackpb.Entry{
		Key: key("10.0.0.1", "10.0.0.2"), SourceEndpointIndex: idx(0), DestinationEndpointIndex: idx(1),
	}))
	// node-b: the very same indices refer to different endpoints, and the
	// connection is the same as node-a's, resolved only on the source side.
	responses <- peerResp("node-b", endpointResp(0, db))
	responses <- peerResp("node-b", endpointResp(1, webRemote))
	responses <- peerResp("node-b", entryResp(&conntrackpb.Entry{
		Key: key("10.0.0.2", "10.0.0.1"), SourceEndpointIndex: idx(0), DestinationEndpointIndex: idx(1),
	}))
	responses <- peerResp("node-b", entryResp(&conntrackpb.Entry{
		Key: key("10.0.0.1", "10.0.0.2"), SourceEndpointIndex: idx(1),
	}))
	// node-c: unresolved observation of an already resolved connection.
	responses <- peerResp("node-c", entryResp(&conntrackpb.Entry{Key: key("10.0.0.1", "10.0.0.2")}))
	// node-c: unresolved connection.
	responses <- peerResp("node-c", entryResp(&conntrackpb.Entry{Key: key("10.0.0.9", "10.0.0.8")}))
	close(responses)

	snap := mergeConntrackResponses(responses)

	var eps []*flowpb.Endpoint
	for ep := range snap.Endpoints() {
		require.EqualValues(t, len(eps), ep.GetIndex())
		eps = append(eps, ep.GetEndpoint())
	}
	require.Equal(t, []*flowpb.Endpoint{webLocal, db}, eps, "web and db must be forwarded once")

	byKey := make(map[ctKey]*conntrackpb.Entry)
	for e := range snap.Entries() {
		byKey[keyOf(e.GetKey())] = e
	}
	require.Len(t, byKey, 3)

	e := byKey[keyOf(key("10.0.0.1", "10.0.0.2"))]
	require.EqualValues(t, 0, e.GetSourceEndpointIndex())
	require.EqualValues(t, 1, e.GetDestinationEndpointIndex())

	e = byKey[keyOf(key("10.0.0.2", "10.0.0.1"))]
	require.EqualValues(t, 1, e.GetSourceEndpointIndex())
	require.EqualValues(t, 0, e.GetDestinationEndpointIndex())

	e = byKey[keyOf(key("10.0.0.9", "10.0.0.8"))]
	require.Nil(t, e.SourceEndpointIndex)
	require.Nil(t, e.DestinationEndpointIndex)
}

func TestMergeConntrackResponses_EndpointsKeptOnCanonicalSwitch(t *testing.T) {
	web := &flowpb.Endpoint{Namespace: "default", PodName: "web"}
	idx := uint32(0)
	k := func(flags uint32) *conntrackpb.Key {
		return &conntrackpb.Key{SourceIp: "10.0.0.1", DestinationIp: "10.0.0.2", Protocol: 6, Flags: flags}
	}

	responses := make(chan *PeerResponse, 4)
	responses <- peerResp("node-a", endpointResp(0, web))
	responses <- peerResp("node-a", entryResp(&conntrackpb.Entry{Key: k(ctstats.TupleFlagIn), SourceEndpointIndex: &idx}))
	responses <- peerResp("node-b", entryResp(&conntrackpb.Entry{Key: k(0)}))
	close(responses)

	snap := mergeConntrackResponses(responses)
	entries := slices.Collect(snap.Entries())
	require.Len(t, entries, 1)
	require.Zero(t, entries[0].GetKey().GetFlags())
	require.EqualValues(t, 0, entries[0].GetSourceEndpointIndex())
	require.Nil(t, entries[0].DestinationEndpointIndex)
}

func TestMergeConntrackResponses_Services(t *testing.T) {
	web := &flowpb.Service{Namespace: "default", Name: "web"}
	db := &flowpb.Service{Namespace: "default", Name: "db"}
	key := func(src, dst string) *conntrackpb.Key {
		return &conntrackpb.Key{SourceIp: src, DestinationIp: dst, DestinationPort: 80, Protocol: 6}
	}
	idx := func(i uint32) *uint32 { return &i }

	responses := make(chan *PeerResponse, 8)
	// The same service has a different index on each node.
	responses <- peerResp("node-a", serviceResp(0, web))
	responses <- peerResp("node-b", serviceResp(0, db))
	responses <- peerResp("node-b", serviceResp(1, web))
	responses <- peerResp("node-a", entryResp(&conntrackpb.Entry{
		Key: key("10.0.0.1", "10.96.0.1"), Value: &conntrackpb.Value{}, DestinationServiceIndex: idx(0),
	}))
	responses <- peerResp("node-b", entryResp(&conntrackpb.Entry{
		Key: key("10.0.0.2", "10.96.0.1"), Value: &conntrackpb.Value{}, DestinationServiceIndex: idx(1),
	}))
	responses <- peerResp("node-b", entryResp(&conntrackpb.Entry{
		Key: key("10.0.0.4", "10.96.0.2"), Value: &conntrackpb.Value{}, DestinationServiceIndex: idx(0),
	}))
	// An index the peer never sent is left unresolved.
	responses <- peerResp("node-a", entryResp(&conntrackpb.Entry{
		Key: key("10.0.0.3", "10.0.0.4"), Value: &conntrackpb.Value{}, DestinationServiceIndex: idx(9),
	}))
	close(responses)

	snap := mergeConntrackResponses(responses)
	var services []*flowpb.Service
	for svc := range snap.Services() {
		require.EqualValues(t, len(services), svc.GetIndex())
		services = append(services, svc.GetService())
	}
	require.Len(t, services, 2)
	require.Equal(t, "web", services[0].GetName())
	require.Equal(t, "db", services[1].GetName())

	for e := range snap.Entries() {
		switch e.GetKey().GetSourceIp() {
		case "10.0.0.1", "10.0.0.2":
			require.EqualValues(t, 0, e.GetDestinationServiceIndex())
		case "10.0.0.4":
			require.EqualValues(t, 1, e.GetDestinationServiceIndex())
		case "10.0.0.3":
			require.Nil(t, e.DestinationServiceIndex)
		}
	}
}

func TestExporterCache(t *testing.T) {
	var fetches atomic.Int32
	fetch := func(ctx context.Context) (<-chan *PeerResponse, func() error) {
		fetches.Add(1)
		ch := make(chan *PeerResponse, 1)
		ch <- peerResp("node-a", entryResp(&conntrackpb.Entry{
			Key:   &conntrackpb.Key{SourceIp: "10.0.0.1", DestinationIp: "10.0.0.2"},
			Value: &conntrackpb.Value{RxPackets: 1},
		}))
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
	fetch := func(ctx context.Context) (<-chan *PeerResponse, func() error) {
		fetches.Add(1)
		ch := make(chan *PeerResponse)
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
