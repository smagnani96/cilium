// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package ctstats

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	conntrackpb "github.com/cilium/cilium/api/v1/conntrack"
)

func TestNodeDedup(t *testing.T) {
	d := NewNodeDedup()

	_, ok := d.Index(nil)
	require.False(t, ok)

	worker := &conntrackpb.Node{Name: "worker", Cluster: "default"}
	idx, ok := d.Index(worker)
	require.True(t, ok)
	require.EqualValues(t, 0, idx)

	again, _ := d.Index(&conntrackpb.Node{Name: "worker", Cluster: "default"})
	require.Equal(t, idx, again)

	other, _ := d.Index(&conntrackpb.Node{Name: "worker", Cluster: "other"})
	require.EqualValues(t, 1, other)

	got := slices.Collect(IndexedNodes(d))
	require.Len(t, got, 2)
	require.Same(t, worker, got[0].GetNode())
	require.EqualValues(t, 1, got[1].GetIndex())
}
