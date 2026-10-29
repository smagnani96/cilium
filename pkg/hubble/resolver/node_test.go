// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package resolver

import (
	"net/netip"
	"testing"

	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"

	iputil "github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/node/addressing"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
)

func TestNodeGetter_GetNodeByAddr(t *testing.T) {
	db := statedb.New()
	nodes, err := node.NewNodeTable(db)
	require.NoError(t, err)

	wtxn := db.WriteTxn(nodes)
	_, _, err = nodes.Insert(wtxn, &node.Node{Node: nodeTypes.Node{
		Name:    "worker",
		Cluster: "default",
		Labels:  map[string]string{"zone": "a", "arch": "arm64"},
		IPAddresses: []nodeTypes.Address{
			{Type: addressing.NodeInternalIP, IP: iputil.AddrFrom(netip.MustParseAddr("192.168.0.1"))},
			{Type: addressing.NodeInternalIP, IP: iputil.AddrFrom(netip.MustParseAddr("fd00::1"))},
		},
	}})
	require.NoError(t, err)
	wtxn.Commit()

	g := NodeGetter{db: db, nodes: nodes}

	for _, ip := range []string{"192.168.0.1", "::ffff:192.168.0.1", "fd00::1"} {
		n := g.GetNodeByAddr(netip.MustParseAddr(ip))
		require.NotNil(t, n, ip)
		require.Equal(t, "worker", n.Name)
		require.Equal(t, "default", n.Cluster)
		require.Equal(t, []string{"arch=arm64", "zone=a"}, n.Labels)
	}

	require.Nil(t, g.GetNodeByAddr(netip.MustParseAddr("192.168.0.2")))
	require.Nil(t, g.GetNodeByAddr(netip.Addr{}))
}
