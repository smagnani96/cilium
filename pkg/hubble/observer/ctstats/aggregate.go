// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package ctstats

import (
	"slices"

	conntrackpb "github.com/cilium/cilium/api/v1/conntrack"
	"github.com/cilium/cilium/pkg/ctstats"
)

func groupByUsesResolved(fields []conntrackpb.AggregationField) bool {
	return slices.ContainsFunc(fields, func(f conntrackpb.AggregationField) bool {
		return f >= conntrackpb.AggregationField_AGGREGATION_FIELD_SOURCE_ENDPOINT
	})
}

// groupKey is what the entries of a group agree on. Indices are unique per
// resolved value in a View, and -1 if unresolved or not grouped by.
type groupKey struct {
	srcIP, dstIP                           string
	srcPort, dstPort, proto, flags         uint32
	srcEP, dstEP, dstSvc, srcNode, dstNode int64
}

func idx(i *uint32) int64 {
	if i == nil {
		return -1
	}
	return int64(*i)
}

func aggregate(v View, groupBy []conntrackpb.AggregationField) View {
	by := func(f conntrackpb.AggregationField) bool { return slices.Contains(groupBy, f) }
	var (
		groups  = map[groupKey]*conntrackpb.Entry{}
		entries []*conntrackpb.Entry
	)
	for e := range v.Entries() {
		// Start from the group the entry belongs to, with only the fields grouped by.
		g := &conntrackpb.Entry{
			Key:   &conntrackpb.Key{Flags: e.GetKey().GetFlags() & ctstats.TupleFlagService},
			Value: &conntrackpb.Value{},
		}
		if by(conntrackpb.AggregationField_AGGREGATION_FIELD_SOURCE_IP) {
			g.Key.SourceIp = e.GetKey().GetSourceIp()
		}
		if by(conntrackpb.AggregationField_AGGREGATION_FIELD_DESTINATION_IP) {
			g.Key.DestinationIp = e.GetKey().GetDestinationIp()
		}
		if by(conntrackpb.AggregationField_AGGREGATION_FIELD_SOURCE_PORT) {
			g.Key.SourcePort = e.GetKey().GetSourcePort()
		}
		if by(conntrackpb.AggregationField_AGGREGATION_FIELD_DESTINATION_PORT) {
			g.Key.DestinationPort = e.GetKey().GetDestinationPort()
		}
		if by(conntrackpb.AggregationField_AGGREGATION_FIELD_PROTOCOL) {
			g.Key.Protocol = e.GetKey().GetProtocol()
		}
		if by(conntrackpb.AggregationField_AGGREGATION_FIELD_SOURCE_ENDPOINT) {
			g.SourceEndpointIndex = e.SourceEndpointIndex
		}
		if by(conntrackpb.AggregationField_AGGREGATION_FIELD_DESTINATION_ENDPOINT) {
			g.DestinationEndpointIndex = e.DestinationEndpointIndex
		}
		if by(conntrackpb.AggregationField_AGGREGATION_FIELD_DESTINATION_SERVICE) {
			g.DestinationServiceIndex = e.DestinationServiceIndex
		}
		if by(conntrackpb.AggregationField_AGGREGATION_FIELD_SOURCE_NODE) {
			g.SourceNodeIndex = e.SourceNodeIndex
		}
		if by(conntrackpb.AggregationField_AGGREGATION_FIELD_DESTINATION_NODE) {
			g.DestinationNodeIndex = e.DestinationNodeIndex
		}

		k := groupKey{
			g.Key.SourceIp, g.Key.DestinationIp,
			g.Key.SourcePort, g.Key.DestinationPort, g.Key.Protocol, g.Key.Flags,
			idx(g.SourceEndpointIndex), idx(g.DestinationEndpointIndex), idx(g.DestinationServiceIndex),
			idx(g.SourceNodeIndex), idx(g.DestinationNodeIndex),
		}
		if prev, ok := groups[k]; ok {
			g = prev
		} else {
			groups[k] = g
			entries = append(entries, g)
		}
		g.Count++
		g.Value.RxPackets += e.GetValue().GetRxPackets()
		g.Value.TxPackets += e.GetValue().GetTxPackets()
		g.Value.RxBytes += e.GetValue().GetRxBytes()
		g.Value.TxBytes += e.GetValue().GetTxBytes()
	}
	return newView(v, entries)
}
