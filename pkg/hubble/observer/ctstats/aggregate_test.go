// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package ctstats

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	conntrackpb "github.com/cilium/cilium/api/v1/conntrack"
	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/ctstats"
)

func TestAggregate(t *testing.T) {
	entry := func(src string, sport uint32, flags uint32, srcEP *uint32, tx uint64) *conntrackpb.Entry {
		return &conntrackpb.Entry{
			Key:                 &conntrackpb.Key{SourceIp: src, SourcePort: sport, DestinationIp: "10.0.0.9", Protocol: 6, Flags: flags},
			Value:               &conntrackpb.Value{TxPackets: tx, TxBytes: 10 * tx},
			SourceEndpointIndex: srcEP,
		}
	}
	v := &fakeView{
		entries: []*conntrackpb.Entry{
			entry("10.0.0.1", 1, 0, ptr(0), 1),
			entry("10.0.0.1", 2, 0, ptr(0), 2),
			entry("10.0.0.2", 3, 0, ptr(1), 4),
			entry("10.0.0.3", 4, 0, nil, 8),
			entry("10.0.0.1", 5, ctstats.TupleFlagService, ptr(0), 16),
		},
		endpoints: []*conntrackpb.IndexedEndpoint{
			{Index: 0, Endpoint: &flowpb.Endpoint{PodName: "a"}},
			{Index: 1, Endpoint: &flowpb.Endpoint{PodName: "b"}},
		},
	}
	type group struct {
		count, tx uint64
		flags     uint32
	}
	collect := func(groupBy ...conntrackpb.AggregationField) (groups []group, out View) {
		q, err := NewQuery(&conntrackpb.GetStatsRequest{Resolve: true, GroupBy: groupBy})
		require.NoError(t, err)
		out = q.Apply(v)
		for e := range out.Entries() {
			groups = append(groups, group{e.GetCount(), e.GetValue().GetTxPackets(), e.GetKey().GetFlags()})
		}
		return groups, out
	}

	// Everything but the service bit is merged.
	groups, _ := collect(conntrackpb.AggregationField_AGGREGATION_FIELD_PROTOCOL)
	require.Equal(t, []group{{4, 15, 0}, {1, 16, ctstats.TupleFlagService}}, groups)

	// The unresolved endpoint is a group of its own, and only what is
	// referenced is kept.
	groups, out := collect(conntrackpb.AggregationField_AGGREGATION_FIELD_SOURCE_ENDPOINT)
	require.Equal(t, []group{{2, 3, 0}, {1, 4, 0}, {1, 8, 0}, {1, 16, ctstats.TupleFlagService}}, groups)
	require.Len(t, slices.Collect(out.Endpoints()), 2)

	groups, out = collect(conntrackpb.AggregationField_AGGREGATION_FIELD_SOURCE_IP, conntrackpb.AggregationField_AGGREGATION_FIELD_SOURCE_PORT)
	require.Len(t, groups, 5)
	require.Empty(t, slices.Collect(out.Endpoints()))

	// Grouping by a resolved field requires resolve.
	_, err := NewQuery(&conntrackpb.GetStatsRequest{GroupBy: []conntrackpb.AggregationField{conntrackpb.AggregationField_AGGREGATION_FIELD_DESTINATION_NODE}})
	require.Error(t, err)
}
