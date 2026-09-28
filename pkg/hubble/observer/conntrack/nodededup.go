// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package conntrack

import (
	"iter"

	observerpb "github.com/cilium/cilium/api/v1/observer"
	resolverTypes "github.com/cilium/cilium/pkg/hubble/resolver/types"
)

// NodeDedup assigns a stable index to each distinct resolved
// source/destination node referenced by ConntrackStatsEntry messages, so a
// GetConntrackStats response stream can carry one ConntrackStatsNode per
// distinct value instead of repeating the same node on every entry that
// shares the same source and/or destination.
//
// Two nodes are considered the same value if their name and cluster are
// equal; labels aren't compared, as they are derived deterministically from
// those fields by the resolver for the duration of a single snapshot.
type NodeDedup struct {
	byKey map[nodeKey]uint32
	list  []*resolverTypes.ResolvedNode
}

// NewNodeDedup creates an empty NodeDedup.
func NewNodeDedup() *NodeDedup {
	return &NodeDedup{byKey: make(map[nodeKey]uint32)}
}

type nodeKey struct {
	name, cluster string
}

// nodeKeyOf mirrors keyOf (see endpointdedup.go), for callers holding a
// *observerpb.ConntrackStatsNode (the wire representation) rather than a
// *resolverTypes.ResolvedNode.
func nodeKeyOf(n *observerpb.ConntrackStatsNode) nodeKey {
	return nodeKey{name: n.GetName(), cluster: n.GetCluster()}
}

// Index returns the index n is assigned in the dedup table, allocating a
// new one the first time this node's value is seen. ok is false if n is
// nil, in which case idx is meaningless.
func (d *NodeDedup) Index(n *resolverTypes.ResolvedNode) (idx uint32, ok bool) {
	if n == nil {
		return 0, false
	}
	k := nodeKey{name: n.Name, cluster: n.Cluster}
	if idx, ok := d.byKey[k]; ok {
		return idx, true
	}
	idx = uint32(len(d.list))
	d.byKey[k] = idx
	d.list = append(d.list, n)
	return idx, true
}

func (d *NodeDedup) List() []*resolverTypes.ResolvedNode {
	return d.list
}

func (d *NodeDedup) Nodes() iter.Seq[*observerpb.ConntrackStatsNode] {
	return func(yield func(*observerpb.ConntrackStatsNode) bool) {
		for i, n := range d.list {
			if !yield(&observerpb.ConntrackStatsNode{
				Index:   uint32(i),
				Name:    n.Name,
				Cluster: n.Cluster,
				Labels:  n.Labels,
			}) {
				return
			}
		}
	}
}
