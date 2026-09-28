// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package conntrack

import (
	"iter"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	observerpb "github.com/cilium/cilium/api/v1/observer"
	resolverTypes "github.com/cilium/cilium/pkg/hubble/resolver/types"
)

// Snapshot is the minimal read view Aggregate needs from a GetConntrackStats
// snapshot. It's satisfied both by pkg/hubble/observer/conntrack/types.Stats
// and by the relay's own Stats (pkg/hubble/relay/observer/conntrack), so
// Aggregate can be shared by the agent's and the relay's observer servers
// alike.
type Snapshot interface {
	Entries() iter.Seq[*observerpb.ConntrackStatsEntry]
	Endpoints() iter.Seq[*observerpb.ConntrackStatsEndpoint]
	Nodes() iter.Seq[*observerpb.ConntrackStatsNode]
}

// Aggregate re-groups stats' entries according to groupBy: entries that
// agree on every field listed in groupBy are merged into a single entry
// whose counters are the sum of every entry folded into it, and every field
// *not* listed is cleared. If groupBy is empty, stats is returned
// unmodified, i.e. every distinct connection is reported individually.
//
// Aggregate never mutates stats, nor the snapshot it was computed from: the
// cached snapshot is intentionally kept at its original, finest granularity,
// since different callers may request different aggregations against the
// very same cache entry, and pre-aggregating it would permanently discard
// the information a coarser caller doesn't need but a finer one still does.
func Aggregate(stats Snapshot, groupBy []observerpb.ConntrackAggregationField) Snapshot {
	fields := newAggregationFields(groupBy)
	if fields.empty() {
		return stats
	}

	// Entries reference Endpoints/Nodes by index, and that index is only
	// meaningful relative to this same snapshot; resolve it to the actual
	// value up front, before ranging over Entries, per Snapshot's contract.
	endpointsByIdx := make(map[uint32]*flowpb.Endpoint)
	for ep := range stats.Endpoints() {
		endpointsByIdx[ep.GetIndex()] = ep.GetEndpoint()
	}
	nodesByIdx := make(map[uint32]*observerpb.ConntrackStatsNode)
	for n := range stats.Nodes() {
		nodesByIdx[n.GetIndex()] = n
	}

	agg := &aggregatedStats{
		entries:   make(map[aggregationKey]*aggregatedValue),
		endpoints: NewEndpointDedup(),
		nodes:     NewNodeDedup(),
	}
	for e := range stats.Entries() {
		agg.merge(e, fields, endpointsByIdx, nodesByIdx)
	}
	return agg
}

// aggregationFields records which of ConntrackStatsEntry's fields the caller
// wants to keep distinct; every other field is collapsed into a single
// group.
type aggregationFields struct {
	sourceIP, sourcePort                bool
	destinationIP, destinationPort      bool
	protocol                            bool
	sourceEndpoint, destinationEndpoint bool
	sourceNode, destinationNode         bool
}

func newAggregationFields(groupBy []observerpb.ConntrackAggregationField) aggregationFields {
	var f aggregationFields
	for _, field := range groupBy {
		switch field {
		case observerpb.ConntrackAggregationField_CONNTRACK_AGGREGATION_FIELD_SOURCE_IP:
			f.sourceIP = true
		case observerpb.ConntrackAggregationField_CONNTRACK_AGGREGATION_FIELD_SOURCE_PORT:
			f.sourcePort = true
		case observerpb.ConntrackAggregationField_CONNTRACK_AGGREGATION_FIELD_DESTINATION_IP:
			f.destinationIP = true
		case observerpb.ConntrackAggregationField_CONNTRACK_AGGREGATION_FIELD_DESTINATION_PORT:
			f.destinationPort = true
		case observerpb.ConntrackAggregationField_CONNTRACK_AGGREGATION_FIELD_PROTOCOL:
			f.protocol = true
		case observerpb.ConntrackAggregationField_CONNTRACK_AGGREGATION_FIELD_SOURCE_ENDPOINT:
			f.sourceEndpoint = true
		case observerpb.ConntrackAggregationField_CONNTRACK_AGGREGATION_FIELD_DESTINATION_ENDPOINT:
			f.destinationEndpoint = true
		case observerpb.ConntrackAggregationField_CONNTRACK_AGGREGATION_FIELD_SOURCE_NODE:
			f.sourceNode = true
		case observerpb.ConntrackAggregationField_CONNTRACK_AGGREGATION_FIELD_DESTINATION_NODE:
			f.destinationNode = true
		}
		// Unrecognized (including the zero/UNKNOWN) values are ignored
		// rather than rejected: they can't express any grouping intent.
	}
	return f
}

func (f aggregationFields) empty() bool {
	return f == aggregationFields{}
}

// aggregationKey identifies the group a ConntrackStatsEntry falls into: fields
// not selected by aggregationFields are left at their zero value, so every
// entry sharing the same selected fields hashes to the same key regardless
// of what its collapsed fields were.
//
// sourceEndpointKey/destinationEndpointKey/sourceNodeKey/destinationNodeKey
// reuse EndpointDedup/NodeDedup's own notion of "same value" (keyOf/
// nodeKeyOf) directly, rather than the *original* snapshot's dedup index:
// two entries with different indices can still be the very same
// human-meaningful Endpoint/node (see keyOf's doc comment for why), so
// comparing indices instead would wrongly report them as separate groups.
// The associated has* field distinguishes a real, resolved group from
// "this side didn't resolve", which is itself a distinct, valid group
// (every unresolved entry is folded together) rather than one to be
// excluded.
type aggregationKey struct {
	sourceIP, destinationIP                   string
	sourcePort, destinationPort               uint32
	protocol                                  uint32
	sourceEndpointKey, destinationEndpointKey endpointKey
	hasSourceEndpoint, hasDestinationEndpoint bool
	sourceNodeKey, destinationNodeKey         nodeKey
	hasSourceNode, hasDestinationNode         bool
}

// aggregatedValue accumulates the summed counters of every ConntrackStatsEntry
// folded into one aggregationKey, plus the resolved Endpoint/node it
// resolves to in the aggregated snapshot's own dedup tables, if any.
type aggregatedValue struct {
	rxPackets, txPackets                      uint64
	rxBytes, txBytes                          uint64
	count                                     uint64
	sourceEndpointIdx, destinationEndpointIdx *uint32
	sourceNodeIdx, destinationNodeIdx         *uint32
}

type aggregatedStats struct {
	entries   map[aggregationKey]*aggregatedValue
	endpoints *EndpointDedup
	nodes     *NodeDedup
}

// merge folds e into the group aggregationFields says it belongs to,
// summing its counters into whatever other entries already share that
// group.
func (a *aggregatedStats) merge(
	e *observerpb.ConntrackStatsEntry,
	fields aggregationFields,
	endpointsByIdx map[uint32]*flowpb.Endpoint,
	nodesByIdx map[uint32]*observerpb.ConntrackStatsNode,
) {
	var k aggregationKey
	if fields.sourceIP {
		k.sourceIP = e.GetKey().GetSourceIp()
	}
	if fields.sourcePort {
		k.sourcePort = e.GetKey().GetSourcePort()
	}
	if fields.destinationIP {
		k.destinationIP = e.GetKey().GetDestinationIp()
	}
	if fields.destinationPort {
		k.destinationPort = e.GetKey().GetDestinationPort()
	}
	if fields.protocol {
		k.protocol = e.GetKey().GetProtocol()
	}
	if fields.sourceEndpoint {
		if idx := e.GetSourceEndpointIndex(); idx != nil {
			k.sourceEndpointKey, k.hasSourceEndpoint = keyOf(endpointsByIdx[idx.GetValue()]), true
		}
	}
	if fields.destinationEndpoint {
		if idx := e.GetDestinationEndpointIndex(); idx != nil {
			k.destinationEndpointKey, k.hasDestinationEndpoint = keyOf(endpointsByIdx[idx.GetValue()]), true
		}
	}
	if fields.sourceNode {
		if idx := e.GetSourceNodeIndex(); idx != nil {
			k.sourceNodeKey, k.hasSourceNode = nodeKeyOf(nodesByIdx[idx.GetValue()]), true
		}
	}
	if fields.destinationNode {
		if idx := e.GetDestinationNodeIndex(); idx != nil {
			k.destinationNodeKey, k.hasDestinationNode = nodeKeyOf(nodesByIdx[idx.GetValue()]), true
		}
	}

	v, ok := a.entries[k]
	if !ok {
		v = &aggregatedValue{}
		a.entries[k] = v
		// Endpoint/node resolution is a pure function of the raw source/
		// destination IP (see resolveEndpoint/resolveNodeIndex), so it's
		// still unambiguous for the group even when the caller didn't ask
		// to group by SOURCE_ENDPOINT/SOURCE_NODE, as long as they grouped
		// by the raw SOURCE_IP itself: every entry folded into this group
		// then necessarily shares the same source IP, and therefore the
		// same resolved Endpoint/node. Without either, a group can mix
		// entries with different, unrelated sources, so nothing is
		// carried over.
		if fields.sourceEndpoint || fields.sourceIP {
			if idx := e.GetSourceEndpointIndex(); idx != nil {
				v.sourceEndpointIdx = dedupEndpointIndex(a.endpoints, endpointsByIdx[idx.GetValue()])
			}
		}
		if fields.destinationEndpoint || fields.destinationIP {
			if idx := e.GetDestinationEndpointIndex(); idx != nil {
				v.destinationEndpointIdx = dedupEndpointIndex(a.endpoints, endpointsByIdx[idx.GetValue()])
			}
		}
		if fields.sourceNode || fields.sourceIP {
			if idx := e.GetSourceNodeIndex(); idx != nil {
				v.sourceNodeIdx = dedupNodeIndex(a.nodes, nodesByIdx[idx.GetValue()])
			}
		}
		if fields.destinationNode || fields.destinationIP {
			if idx := e.GetDestinationNodeIndex(); idx != nil {
				v.destinationNodeIdx = dedupNodeIndex(a.nodes, nodesByIdx[idx.GetValue()])
			}
		}
	}

	val := e.GetValue()
	v.rxPackets += val.GetRxPackets()
	v.txPackets += val.GetTxPackets()
	v.rxBytes += val.GetRxBytes()
	v.txBytes += val.GetTxBytes()
	v.count += 1
}

// dedupNodeIndex records n (converted from its wire representation) in
// dedup and returns its index, or nil if n is nil.
func dedupNodeIndex(dedup *NodeDedup, n *observerpb.ConntrackStatsNode) *uint32 {
	if n == nil {
		return nil
	}
	idx, ok := dedup.Index(&resolverTypes.ResolvedNode{
		Name:    n.GetName(),
		Cluster: n.GetCluster(),
		Labels:  n.GetLabels(),
	})
	if !ok {
		return nil
	}
	return &idx
}

// Entries lazily yields one ConntrackStatsEntry per aggregated group.
func (a *aggregatedStats) Entries() iter.Seq[*observerpb.ConntrackStatsEntry] {
	return func(yield func(*observerpb.ConntrackStatsEntry) bool) {
		for k, v := range a.entries {
			e := &observerpb.ConntrackStatsEntry{
				Key: &observerpb.ConntrackStatsKey{
					SourceIp:        k.sourceIP,
					SourcePort:      k.sourcePort,
					DestinationIp:   k.destinationIP,
					DestinationPort: k.destinationPort,
					Protocol:        k.protocol,
				},
				Value: &observerpb.ConntrackStatsValue{
					RxPackets: v.rxPackets,
					TxPackets: v.txPackets,
					RxBytes:   v.rxBytes,
					TxBytes:   v.txBytes,
				},
				Count:                    v.count,
				SourceEndpointIndex:      Wrap(v.sourceEndpointIdx),
				DestinationEndpointIndex: Wrap(v.destinationEndpointIdx),
				SourceNodeIndex:          Wrap(v.sourceNodeIdx),
				DestinationNodeIndex:     Wrap(v.destinationNodeIdx),
			}
			if !yield(e) {
				return
			}
		}
	}
}

// Endpoints lazily yields one ConntrackStatsEndpoint per distinct resolved
// source/destination Endpoint referenced by Entries.
func (a *aggregatedStats) Endpoints() iter.Seq[*observerpb.ConntrackStatsEndpoint] {
	return a.endpoints.Endpoints()
}

// Nodes lazily yields one ConntrackStatsNode per distinct resolved
// source/destination node referenced by Entries.
func (a *aggregatedStats) Nodes() iter.Seq[*observerpb.ConntrackStatsNode] {
	return a.nodes.Nodes()
}
