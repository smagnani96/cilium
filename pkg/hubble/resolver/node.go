// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package resolver

import (
	"net/netip"

	"github.com/cilium/statedb"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/hubble/resolver/types"
	"github.com/cilium/cilium/pkg/node"
)

type NodeGetter struct {
	db    *statedb.DB
	nodes statedb.Table[*node.Node]
}

func NewNodeGetter(db *statedb.DB, nodes statedb.Table[*node.Node]) types.NodeGetter {
	return &NodeGetter{db: db, nodes: nodes}
}

func (r *NodeGetter) GetNodeNameByIP(ip netip.Addr) string {
	if !ip.IsValid() || r.nodes == nil {
		return ""
	}
	txn := r.db.ReadTxn()
	for n := range r.nodes.List(txn, node.NodeByAddress(cmtypes.AddrClusterFrom(ip, 0))) {
		return n.Fullname()
	}
	return ""
}
