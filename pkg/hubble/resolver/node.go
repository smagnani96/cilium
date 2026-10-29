// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package resolver

import (
	"net/netip"
	"slices"

	"github.com/cilium/statedb"

	conntrackpb "github.com/cilium/cilium/api/v1/conntrack"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/hubble/resolver/types"
	"github.com/cilium/cilium/pkg/node"
)

// NodeGetter implements types.NodeGetter using Cilium's node table.
type NodeGetter struct {
	db    *statedb.DB
	nodes statedb.Table[*node.Node]
}

func NewNodeGetter(db *statedb.DB, nodes statedb.Table[*node.Node]) types.NodeGetter {
	return &NodeGetter{db: db, nodes: nodes}
}

// GetNodeByAddr implements types.NodeGetter. It looks up the node by IP.
func (g *NodeGetter) GetNodeByAddr(ip netip.Addr) *conntrackpb.Node {
	if !ip.IsValid() {
		return nil
	}
	n, _, found := g.nodes.Get(g.db.ReadTxn(), node.NodeByAddress(cmtypes.AddrClusterFrom(ip.Unmap(), 0)))
	if !found {
		return nil
	}
	labels := make([]string, 0, len(n.Labels))
	for k, v := range n.Labels {
		labels = append(labels, k+"="+v)
	}
	slices.Sort(labels)
	return &conntrackpb.Node{Name: n.Name, Cluster: n.Cluster, Labels: labels}
}
