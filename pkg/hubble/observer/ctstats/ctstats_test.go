// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package ctstats

import (
	"context"
	"net/netip"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	conntrackpb "github.com/cilium/cilium/api/v1/conntrack"
	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/ctstats"
	resolverTypes "github.com/cilium/cilium/pkg/hubble/resolver/types"
	"github.com/cilium/cilium/pkg/hubble/testutils"
	"github.com/cilium/cilium/pkg/u8proto"
)

func TestSnapshotEntries(t *testing.T) {
	tuple := func(flags uint8) ctstats.Tuple {
		return ctstats.Tuple{
			Src: netip.MustParseAddr("10.0.0.1"), Dst: netip.MustParseAddr("10.0.0.2"),
			SrcPort: 1234, DstPort: 80, Proto: 6, Flags: flags,
		}
	}
	other := tuple(0)
	other.SrcPort = 4321

	stats := &ctstats.Snapshot{Entries: map[ctstats.Tuple]ctstats.Entry{
		tuple(0):                   {Value: ctstats.Value{TxPackets: 3}, Alive: true},
		tuple(ctstats.TupleFlagIn): {Value: ctstats.Value{RxPackets: 3}, Alive: true}, // mirror
		other:                      {Value: ctstats.Value{TxBytes: 7}},
		func() ctstats.Tuple { // IN without OUT counterpart is kept
			x := other
			x.SrcPort = 1
			x.Flags = ctstats.TupleFlagIn
			return x
		}(): {Alive: true},
	}}

	e := &Exporter{epGetter: &testutils.NoopEndpointGetter, svcGetter: &testutils.NoopServiceGetter, nodeGetter: &testutils.NoopNodeGetter}
	got := slices.Collect(e.resolve(stats).Entries())
	require.Len(t, got, 3)

	var seen int
	for _, e := range got {
		switch e.Key.SourcePort {
		case 1234:
			seen++
			require.Zero(t, e.Key.Flags)
			require.EqualValues(t, 3, e.Value.TxPackets)
			require.True(t, e.State.Alive)
			require.Equal(t, "10.0.0.1", e.Key.SourceIp)
		case 4321:
			seen++
			require.False(t, e.State.Alive)
			require.EqualValues(t, 7, e.Value.TxBytes)
		}
	}
	require.Equal(t, 2, seen)

	require.Empty(t, slices.Collect((&Snapshot{}).Entries()))
}

func TestExporterEndpoints(t *testing.T) {
	var (
		web = netip.MustParseAddr("10.0.0.1")
		// A second address of the web pod.
		webV6 = netip.MustParseAddr("fd00::1")
		db    = netip.MustParseAddr("10.0.0.2")
		world = netip.MustParseAddr("1.1.1.1")
		// The address of a service, which is not resolved.
		svc = netip.MustParseAddr("10.96.0.1")
	)
	pods := map[netip.Addr]*flowpb.Endpoint{
		web:   {Namespace: "default", PodName: "web", PodUid: "web-uid"},
		webV6: {Namespace: "default", PodName: "web", PodUid: "web-uid"},
		db:    {Namespace: "default", PodName: "db", PodUid: "db-uid"},
		svc:   {Namespace: "default", PodName: "svc", PodUid: "svc-uid"},
	}

	var resolutions atomic.Int32
	epGetter := &testutils.FakeEndpointGetter{
		OnResolveEndpoint: func(ip netip.Addr, _ uint32, _ resolverTypes.DatapathContext) *flowpb.Endpoint {
			resolutions.Add(1)
			return pods[ip]
		},
	}

	conns := []ctstats.Tuple{
		{Src: web, Dst: db, SrcPort: 1, DstPort: 80, Proto: 6},
		{Src: webV6, Dst: db, SrcPort: 2, DstPort: 80, Proto: 6},
		{Src: db, Dst: world, SrcPort: 3, DstPort: 443, Proto: 6},
		{Src: web, Dst: svc, SrcPort: 4, DstPort: 80, Proto: 6, Flags: ctstats.TupleFlagService},
	}
	cache := ctstats.New(func(_ context.Context, yield func(ctstats.Tuple, ctstats.Value) bool) error {
		for _, c := range conns {
			yield(c, ctstats.Value{})
		}
		return nil
	}, time.Hour, 10)
	exporter := NewExporter(cache, epGetter, &testutils.NoopServiceGetter, &testutils.NoopNodeGetter)

	var snap *Snapshot
	for range 3 {
		var err error
		snap, err = exporter.Snapshot(t.Context())
		require.NoError(t, err)
	}
	// web, webV6, db and world, only once despite the repeated calls. The
	// destination of the service entry is skipped.
	require.EqualValues(t, 4, resolutions.Load())

	// The indices depend on the order the connections are resolved in.
	byPod := make(map[string]uint32)
	for ep := range snap.Endpoints() {
		byPod[ep.GetEndpoint().GetPodName()] = ep.GetIndex()
	}
	require.Len(t, byPod, 2, "the two addresses of web must share the endpoint")
	require.Contains(t, byPod, "web")
	require.Contains(t, byPod, "db")

	for e := range snap.Entries() {
		switch e.GetKey().GetSourcePort() {
		case 1, 2:
			require.Equal(t, byPod["web"], e.GetSourceEndpointIndex())
			require.Equal(t, byPod["db"], e.GetDestinationEndpointIndex())
		case 3:
			require.Equal(t, byPod["db"], e.GetSourceEndpointIndex())
			require.Nil(t, e.DestinationEndpointIndex, "unresolved endpoint must be unset")
		case 4:
			require.Equal(t, byPod["web"], e.GetSourceEndpointIndex())
			require.Nil(t, e.DestinationEndpointIndex, "service address must not be resolved")
		}
	}

	// A refreshed cache is resolved again.
	exporter = NewExporter(ctstats.New(func(_ context.Context, yield func(ctstats.Tuple, ctstats.Value) bool) error {
		yield(conns[0], ctstats.Value{})
		return nil
	}, time.Nanosecond, 10), epGetter, &testutils.NoopServiceGetter, &testutils.NoopNodeGetter)
	resolutions.Store(0)
	for range 2 {
		_, err := exporter.Snapshot(t.Context())
		require.NoError(t, err)
		time.Sleep(time.Millisecond)
	}
	require.EqualValues(t, 4, resolutions.Load())
}

func TestExporterServices(t *testing.T) {
	var (
		client  = netip.MustParseAddr("10.0.0.1")
		backend = netip.MustParseAddr("10.0.0.2")
		vip     = netip.MustParseAddr("10.96.0.1")
	)
	var lookups atomic.Int32
	svcGetter := &testutils.FakeServiceGetter{
		OnGetServiceByAddr: func(ip netip.Addr, port uint16, proto u8proto.U8proto) *flowpb.Service {
			lookups.Add(1)
			if ip == vip && port == 80 && proto == u8proto.TCP {
				return &flowpb.Service{Namespace: "default", Name: "web"}
			}
			return nil
		},
	}

	svc := func(t ctstats.Tuple) ctstats.Tuple {
		t.Flags = ctstats.TupleFlagService
		return t
	}
	conns := []ctstats.Tuple{
		svc(ctstats.Tuple{Src: client, Dst: vip, SrcPort: 1, DstPort: 80, Proto: 6}),
		svc(ctstats.Tuple{Src: client, Dst: vip, SrcPort: 2, DstPort: 80, Proto: 6}),
		// The protocol is part of the lookup.
		svc(ctstats.Tuple{Src: client, Dst: vip, SrcPort: 3, DstPort: 80, Proto: 17}),
		// Regular entries are keyed by the backend, hence never looked up.
		{Src: vip, Dst: client, SrcPort: 80, DstPort: 4, Proto: 6},
		{Src: client, Dst: backend, SrcPort: 5, DstPort: 8080, Proto: 6},
	}
	cache := ctstats.New(func(_ context.Context, yield func(ctstats.Tuple, ctstats.Value) bool) error {
		for _, c := range conns {
			yield(c, ctstats.Value{})
		}
		return nil
	}, time.Hour, 10)
	exporter := NewExporter(cache, &testutils.NoopEndpointGetter, svcGetter, &testutils.NoopNodeGetter)

	var snap *Snapshot
	for range 3 {
		var err error
		snap, err = exporter.Snapshot(t.Context())
		require.NoError(t, err)
	}
	// Each address, port and protocol of a service entry only once despite
	// the repeated calls.
	require.EqualValues(t, 2, lookups.Load())

	var services []*flowpb.Service
	for svc := range snap.Services() {
		require.EqualValues(t, len(services), svc.GetIndex())
		services = append(services, svc.GetService())
	}
	require.Len(t, services, 1, "all the matches must share the service")
	require.Equal(t, "web", services[0].GetName())

	for e := range snap.Entries() {
		switch e.GetKey().GetSourcePort() {
		case 1, 2:
			require.EqualValues(t, 0, e.GetDestinationServiceIndex())
		case 3:
			require.Nil(t, e.DestinationServiceIndex, "unresolved service must be unset")
		case 5, 80:
			require.Nil(t, e.DestinationServiceIndex, "regular entries must not be looked up")
		}
	}
}

func TestExporterNodes(t *testing.T) {
	var (
		pod     = netip.MustParseAddr("10.0.0.1")
		node    = netip.MustParseAddr("192.168.0.1")
		nodeV6  = netip.MustParseAddr("fd00::1")
		world   = netip.MustParseAddr("1.1.1.1")
		vip     = netip.MustParseAddr("10.96.0.1")
		workers = map[netip.Addr]*conntrackpb.Node{
			node:   {Name: "worker", Labels: []string{"zone=a"}},
			nodeV6: {Name: "worker", Labels: []string{"zone=a"}},
			// A pod is never looked up, even if its address belongs to a node.
			pod: {Name: "other"},
			vip: {Name: "other"},
		}
	)
	epGetter := &testutils.FakeEndpointGetter{
		OnResolveEndpoint: func(ip netip.Addr, _ uint32, _ resolverTypes.DatapathContext) *flowpb.Endpoint {
			if ip == pod {
				return &flowpb.Endpoint{Namespace: "default", PodName: "web"}
			}
			return &flowpb.Endpoint{Labels: []string{"reserved:host"}}
		},
	}
	var lookups atomic.Int32
	nodeGetter := &testutils.FakeNodeGetter{
		OnGetNodeByAddr: func(ip netip.Addr) *conntrackpb.Node {
			lookups.Add(1)
			return workers[ip]
		},
	}

	conns := []ctstats.Tuple{
		{Src: pod, Dst: node, SrcPort: 1, DstPort: 80, Proto: 6},
		{Src: pod, Dst: nodeV6, SrcPort: 2, DstPort: 80, Proto: 6},
		{Src: node, Dst: world, SrcPort: 3, DstPort: 443, Proto: 6},
		{Src: pod, Dst: vip, SrcPort: 4, DstPort: 80, Proto: 6, Flags: ctstats.TupleFlagService},
	}
	cache := ctstats.New(func(_ context.Context, yield func(ctstats.Tuple, ctstats.Value) bool) error {
		for _, c := range conns {
			yield(c, ctstats.Value{})
		}
		return nil
	}, time.Hour, 10)
	exporter := NewExporter(cache, epGetter, &testutils.NoopServiceGetter, nodeGetter)

	var snap *Snapshot
	for range 3 {
		var err error
		snap, err = exporter.Snapshot(t.Context())
		require.NoError(t, err)
	}
	// node, nodeV6 and world, only once despite the repeated calls.
	require.EqualValues(t, 3, lookups.Load())

	var nodes []*conntrackpb.Node
	for n := range snap.Nodes() {
		require.EqualValues(t, len(nodes), n.GetIndex())
		nodes = append(nodes, n.GetNode())
	}
	require.Len(t, nodes, 1, "the two addresses of the node must share it")
	require.Equal(t, "worker", nodes[0].GetName())

	for e := range snap.Entries() {
		switch e.GetKey().GetSourcePort() {
		case 1, 2:
			require.Nil(t, e.SourceNodeIndex)
			require.EqualValues(t, 0, e.GetDestinationNodeIndex())
		case 3:
			require.EqualValues(t, 0, e.GetSourceNodeIndex())
			require.Nil(t, e.DestinationNodeIndex, "unresolved node must be unset")
		case 4:
			require.Nil(t, e.SourceNodeIndex)
			require.Nil(t, e.DestinationNodeIndex, "service address must not be resolved")
		}
	}
}
