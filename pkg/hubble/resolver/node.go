// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package resolver

import (
	"fmt"
	"net/netip"
	"slices"

	"github.com/cilium/cilium/pkg/hubble/resolver/types"
	"github.com/cilium/cilium/pkg/node/manager"
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

// ResolveNode implements types.NodeGetter.
func (g *NodeGetter) ResolveNode(ip netip.Addr) *types.ResolvedNode {
	if g == nil || g.nodeManager == nil || !ip.IsValid() {
		return nil
	}
	identity, ok := g.nodeManager.GetNodeIdentityByIP(ip)
	if !ok {
		return nil
	}
	n, ok := g.nodeManager.GetNodeByIdentity(identity)
	if !ok {
		return &types.ResolvedNode{Name: identity.Name, Cluster: identity.Cluster}
	}
	return &types.ResolvedNode{
		Name:    identity.Name,
		Cluster: identity.Cluster,
		Labels:  sortedLabels(n.Labels),
	}
}

// sortedLabels formats a node's raw label map as a sorted "key=value" slice.
func sortedLabels(labels map[string]string) []string {
	if len(labels) == 0 {
		return nil
	}
	out := make([]string, 0, len(labels))
	for k, v := range labels {
		out = append(out, fmt.Sprintf("%s=%s", k, v))
	}
	slices.Sort(out)
	return out
}
