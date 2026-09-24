// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package conntrack

import (
	"context"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	observerpb "github.com/cilium/cilium/api/v1/observer"
	resolverTypes "github.com/cilium/cilium/pkg/hubble/resolver/types"
	"github.com/cilium/cilium/pkg/hubble/testutils"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/tuple"
	"github.com/cilium/cilium/pkg/types"
	"github.com/cilium/hive/hivetest"
)

type mockCTStatsMaps struct{}

func (m *mockCTStatsMaps) DumpEntries(ctx context.Context, fn func(key ctmap.CtKey, values ctmap.StatsValues) bool) error {
	return nil
}

func (m *mockCTStatsMaps) MaxEntries() int {
	return 0
}

func TestConntrackExporter_Disabled(t *testing.T) {
	c := newCTStatsExporter(Config{}, &option.DaemonConfig{BPFConntrackAccounting: false}, &mockCTStatsMaps{}, hivetest.Logger(t), nil)
	require.False(t, c.Enabled())
	snap, err := c.GetConntrackStats(t.Context())
	require.ErrorIs(t, err, ErrExporterDisabled)
	require.Nil(t, snap)
}

func TestConntrackExporter_Enabled(t *testing.T) {
	c := newCTStatsExporter(Config{}, &option.DaemonConfig{BPFConntrackAccounting: true}, &mockCTStatsMaps{}, hivetest.Logger(t), nil)
	require.True(t, c.Enabled())
	snap1, err := c.GetConntrackStats(t.Context())
	require.NoError(t, err)
	require.NotNil(t, snap1)
}

// newCtKey4 builds a raw IPv4 conntrack key as the datapath would store it:
// address field names are reversed relative to the original-direction
// client/server tuple (see ctKeyToTuple's doc comment).
func newCtKey4(clientAddr string, clientPort uint16, serverAddr string, serverPort uint16, flags uint8) *ctmap.CtKey4Global {
	var dest, source types.IPv4
	dest.FromAddr(netip.MustParseAddr(clientAddr))
	source.FromAddr(netip.MustParseAddr(serverAddr))
	return &ctmap.CtKey4Global{
		TupleKey4Global: tuple.TupleKey4Global{
			TupleKey4: tuple.TupleKey4{
				DestAddr:   dest,
				SourceAddr: source,
				DestPort:   serverPort,
				SourcePort: clientPort,
				NextHeader: 17, // UDP
				Flags:      flags,
			},
		},
	}
}

// TestCtStats_MergeInOutMirror verifies that a TUPLE_F_OUT/TUPLE_F_IN mirror
// pair for the same connection (RX/TX swapped, see bpf/lib/conntrack.h) is
// collapsed into a single entry using the canonical TUPLE_F_OUT counters,
// instead of being kept as two rows or having its counters summed.
func TestCtStats_MergeInOutMirror(t *testing.T) {
	stats := &ctStats{entries: make(map[mergeKey]*ctEntry)}

	outKey := newCtKey4("10.244.0.6", 40924, "10.244.1.151", 53, ctmap.TUPLE_F_OUT)
	outValue := ctmap.StatsValues{{RxPackets: 1, RxBytes: 205, TxPackets: 1, TxBytes: 112}}
	stats.merge(outKey, outValue, nil)

	inKey := newCtKey4("10.244.0.6", 40924, "10.244.1.151", 53, ctmap.TUPLE_F_IN)
	inValue := ctmap.StatsValues{{RxPackets: 1, RxBytes: 112, TxPackets: 1, TxBytes: 205}}
	stats.merge(inKey, inValue, nil)

	require.Len(t, stats.entries, 1)
	var got *ctEntry
	for _, e := range stats.entries {
		got = e
	}
	require.Equal(t, uint8(ctmap.TUPLE_F_OUT), got.flags)
	require.Equal(t, uint64(1), got.value.RxPackets)
	require.Equal(t, uint64(205), got.value.RxBytes)
	require.Equal(t, uint64(1), got.value.TxPackets)
	require.Equal(t, uint64(112), got.value.TxBytes)
}

// TestCtStats_MergeInOutMirror_ReverseOrder verifies the merge is
// order-independent: the canonical TUPLE_F_OUT entry wins even if the
// TUPLE_F_IN mirror is observed first.
func TestCtStats_MergeInOutMirror_ReverseOrder(t *testing.T) {
	stats := &ctStats{entries: make(map[mergeKey]*ctEntry)}

	inKey := newCtKey4("10.244.0.6", 40924, "10.244.1.151", 53, ctmap.TUPLE_F_IN)
	inValue := ctmap.StatsValues{{RxPackets: 1, RxBytes: 112, TxPackets: 1, TxBytes: 205}}
	stats.merge(inKey, inValue, nil)

	outKey := newCtKey4("10.244.0.6", 40924, "10.244.1.151", 53, ctmap.TUPLE_F_OUT)
	outValue := ctmap.StatsValues{{RxPackets: 1, RxBytes: 205, TxPackets: 1, TxBytes: 112}}
	stats.merge(outKey, outValue, nil)

	require.Len(t, stats.entries, 1)
	var got *ctEntry
	for _, e := range stats.entries {
		got = e
	}
	require.Equal(t, uint8(ctmap.TUPLE_F_OUT), got.flags)
	require.Equal(t, uint64(205), got.value.RxBytes)
}

// TestCtStats_MergeKeepsServiceEntryDistinct verifies that a
// TUPLE_F_SERVICE entry is never folded into an IN/OUT entry, even when it
// shares the same raw address/port bytes (e.g. a hairpin/self-selecting
// backend), since it represents a different hop of the connection.
func TestCtStats_MergeKeepsServiceEntryDistinct(t *testing.T) {
	stats := &ctStats{entries: make(map[mergeKey]*ctEntry)}

	outKey := newCtKey4("10.244.0.6", 40924, "10.244.1.151", 53, ctmap.TUPLE_F_OUT)
	stats.merge(outKey, ctmap.StatsValues{{RxPackets: 1, RxBytes: 205, TxPackets: 1, TxBytes: 112}}, nil)

	svcKey := newCtKey4("10.244.0.6", 40924, "10.244.1.151", 53, ctmap.TUPLE_F_SERVICE)
	stats.merge(svcKey, ctmap.StatsValues{{RxPackets: 1, RxBytes: 205, TxPackets: 1, TxBytes: 112}}, nil)

	require.Len(t, stats.entries, 2)
}

func TestCtStats_MergeResolvesAndDedupsEndpoints(t *testing.T) {
	server := &flowpb.Endpoint{ID: 42, Namespace: "default", PodName: "server"}
	epGetter := &testutils.FakeEndpointGetter{
		OnResolveEndpoint: func(ip netip.Addr, _ uint32, _ resolverTypes.DatapathContext) *flowpb.Endpoint {
			if ip.String() == "10.244.1.151" {
				return server
			}
			return nil
		},
	}

	stats := &ctStats{entries: make(map[mergeKey]*ctEntry), endpoints: NewEndpointDedup()}

	firstKey := newCtKey4("10.244.0.6", 40924, "10.244.1.151", 53, ctmap.TUPLE_F_OUT)
	stats.merge(firstKey, ctmap.StatsValues{{RxPackets: 1}}, epGetter)

	secondKey := newCtKey4("10.244.0.7", 51000, "10.244.1.151", 53, ctmap.TUPLE_F_OUT)
	stats.merge(secondKey, ctmap.StatsValues{{RxPackets: 1}}, epGetter)

	require.Len(t, stats.entries, 2)

	var endpoints []*observerpb.ConntrackStatsEndpoint
	for e := range stats.Endpoints() {
		endpoints = append(endpoints, e)
	}
	require.Len(t, endpoints, 1)
	require.True(t, proto.Equal(server, endpoints[0].GetEndpoint()))

	for _, e := range stats.entries {
		require.Nil(t, e.srcEndpointIdx)
		require.NotNil(t, e.dstEndpointIdx)
		require.Equal(t, endpoints[0].GetIndex(), *e.dstEndpointIdx)
	}
}
