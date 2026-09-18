// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package resolver

import (
	"net/netip"

	"github.com/cilium/cilium/pkg/hubble/resolver/types"
	"github.com/cilium/cilium/pkg/node/manager"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
)

// NodeGetter implements types.NodeGetter using Cilium's node manager. It
// resolves IP addresses that belong to a cluster node, rather than an
// endpoint, to the owning node's identity.
type NodeGetter struct {
	nodeManager manager.NodeManager
}

func NewNodeGetter(nodeManager manager.NodeManager) types.NodeGetter {
	return &NodeGetter{nodeManager: nodeManager}
}

func (g *NodeGetter) GetNodeIdentityByIP(ip netip.Addr) (nodeTypes.Identity, bool) {
	if g.nodeManager == nil {
		return nodeTypes.Identity{}, false
	}
	return g.nodeManager.GetNodeIdentityByIP(ip)
}
