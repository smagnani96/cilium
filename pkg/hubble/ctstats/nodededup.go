// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package ctstats

import (
	"iter"

	conntrackpb "github.com/cilium/cilium/api/v1/conntrack"
)

type NodeDedup = Dedup[nodeKey, *conntrackpb.Node]

type nodeKey struct {
	cluster, name string
}

// NewNodeDedup returns a Dedup of resolved nodes, which are the same if they
// have the same cluster and name.
func NewNodeDedup() *NodeDedup {
	return newDedup(func(n *conntrackpb.Node) nodeKey {
		return nodeKey{cluster: n.GetCluster(), name: n.GetName()}
	})
}

func IndexedNodes(d *NodeDedup) iter.Seq[*conntrackpb.IndexedNode] {
	return func(yield func(*conntrackpb.IndexedNode) bool) {
		for i, n := range d.All() {
			if !yield(&conntrackpb.IndexedNode{Index: i, Node: n}) {
				return
			}
		}
	}
}
