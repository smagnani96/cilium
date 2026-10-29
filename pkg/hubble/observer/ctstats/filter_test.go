// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package ctstats

import (
	"iter"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	conntrackpb "github.com/cilium/cilium/api/v1/conntrack"
	flowpb "github.com/cilium/cilium/api/v1/flow"
)

type fakeView struct {
	entries   []*conntrackpb.Entry
	endpoints []*conntrackpb.IndexedEndpoint
	services  []*conntrackpb.IndexedService
	nodes     []*conntrackpb.IndexedNode
}

func (v *fakeView) Entries() iter.Seq[*conntrackpb.Entry] { return slices.Values(v.entries) }
func (v *fakeView) Endpoints() iter.Seq[*conntrackpb.IndexedEndpoint] {
	return slices.Values(v.endpoints)
}
func (v *fakeView) Services() iter.Seq[*conntrackpb.IndexedService] { return slices.Values(v.services) }
func (v *fakeView) Nodes() iter.Seq[*conntrackpb.IndexedNode]       { return slices.Values(v.nodes) }

func ptr(i uint32) *uint32 { return &i }

func TestNewQuery(t *testing.T) {
	for name, req := range map[string]*conntrackpb.GetStatsRequest{
		"endpoint without resolve": {Filter: &conntrackpb.Filter{SourceEndpoint: []string{"a"}}},
		"service without resolve":  {Filter: &conntrackpb.Filter{DestinationService: []string{"a"}}},
		"node without resolve":     {Filter: &conntrackpb.Filter{DestinationNode: []string{"a"}}},
		"malformed IP":             {Filter: &conntrackpb.Filter{SourceIp: []string{"10.0.0"}}},
		"malformed CIDR":           {Filter: &conntrackpb.Filter{DestinationIp: []string{"10.0.0.0/33"}}},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := NewQuery(req)
			require.Error(t, err)
		})
	}

	_, err := NewQuery(&conntrackpb.GetStatsRequest{
		Resolve: true,
		Filter:  &conntrackpb.Filter{SourceEndpoint: []string{"a"}, SourceIp: []string{"10.0.0.0/8", "::1"}},
	})
	require.NoError(t, err)
}

func TestFilter(t *testing.T) {
	entry := func(src, dst string, dport uint32, srcEP, dstSvc, dstNode *uint32) *conntrackpb.Entry {
		return &conntrackpb.Entry{
			Key:                     &conntrackpb.Key{SourceIp: src, DestinationIp: dst, DestinationPort: dport, Protocol: 6},
			SourceEndpointIndex:     srcEP,
			DestinationServiceIndex: dstSvc,
			DestinationNodeIndex:    dstNode,
		}
	}
	v := &fakeView{
		entries: []*conntrackpb.Entry{
			entry("10.0.0.1", "10.96.0.1", 80, ptr(0), ptr(0), nil),
			entry("10.0.0.2", "192.168.0.1", 22, ptr(1), nil, ptr(0)),
			entry("1.1.1.1", "10.0.0.1", 80, nil, nil, nil),
		},
		endpoints: []*conntrackpb.IndexedEndpoint{
			{Index: 0, Endpoint: &flowpb.Endpoint{Namespace: "ns1", PodName: "web-1"}},
			{Index: 1, Endpoint: &flowpb.Endpoint{Namespace: "ns2", PodName: "db-1"}},
		},
		services: []*conntrackpb.IndexedService{{Index: 0, Service: &flowpb.Service{Namespace: "ns1", Name: "web"}}},
		nodes:    []*conntrackpb.IndexedNode{{Index: 0, Node: &conntrackpb.Node{Name: "worker", Cluster: "c1"}}},
	}

	for name, tc := range map[string]struct {
		filter *conntrackpb.Filter
		want   []string // source IPs
	}{
		"CIDR":                  {&conntrackpb.Filter{SourceIp: []string{"10.0.0.0/24"}}, []string{"10.0.0.1", "10.0.0.2"}},
		"IP or port":            {&conntrackpb.Filter{SourceIp: []string{"1.1.1.1"}, DestinationPort: []uint32{80}}, []string{"1.1.1.1"}},
		"endpoint prefix":       {&conntrackpb.Filter{SourceEndpoint: []string{"ns1/we"}}, []string{"10.0.0.1"}},
		"endpoint any ns":       {&conntrackpb.Filter{SourceEndpoint: []string{"db"}}, []string{"10.0.0.2"}},
		"endpoint wrong ns":     {&conntrackpb.Filter{SourceEndpoint: []string{"ns2/web"}}, nil},
		"service":               {&conntrackpb.Filter{DestinationService: []string{"ns1/web"}}, []string{"10.0.0.1"}},
		"node name":             {&conntrackpb.Filter{DestinationNode: []string{"worker"}}, []string{"10.0.0.2"}},
		"node cluster and name": {&conntrackpb.Filter{DestinationNode: []string{"c1/worker"}}, []string{"10.0.0.2"}},
		"node wrong cluster":    {&conntrackpb.Filter{DestinationNode: []string{"c2/worker"}}, nil},
	} {
		t.Run(name, func(t *testing.T) {
			q, err := NewQuery(&conntrackpb.GetStatsRequest{Resolve: true, Filter: tc.filter})
			require.NoError(t, err)
			var got []string
			for e := range q.Apply(v).Entries() {
				got = append(got, e.GetKey().GetSourceIp())
			}
			require.Equal(t, tc.want, got)
		})
	}

	// Only what the matching entries reference is kept.
	q, err := NewQuery(&conntrackpb.GetStatsRequest{Resolve: true, Filter: &conntrackpb.Filter{SourceIp: []string{"10.0.0.2"}}})
	require.NoError(t, err)
	out := q.Apply(v)
	require.Len(t, slices.Collect(out.Endpoints()), 1)
	require.EqualValues(t, 1, slices.Collect(out.Endpoints())[0].GetIndex())
	require.Empty(t, slices.Collect(out.Services()))
	require.Len(t, slices.Collect(out.Nodes()), 1)
}
