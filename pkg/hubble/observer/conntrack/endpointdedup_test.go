// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package conntrack

import (
	"testing"

	"github.com/stretchr/testify/require"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	observerpb "github.com/cilium/cilium/api/v1/observer"
)

func TestEndpointDedup(t *testing.T) {
	d := NewEndpointDedup()

	_, ok := d.Index(nil)
	require.False(t, ok)

	a := &flowpb.Endpoint{ID: 1, Namespace: "default", PodName: "a"}
	idxA, ok := d.Index(a)
	require.True(t, ok)
	require.EqualValues(t, 0, idxA)

	aAgain := &flowpb.Endpoint{ID: 1, Namespace: "default", PodName: "a"}
	idxAAgain, ok := d.Index(aAgain)
	require.True(t, ok)
	require.Equal(t, idxA, idxAAgain)

	b := &flowpb.Endpoint{ID: 2, Namespace: "default", PodName: "b"}
	idxB, ok := d.Index(b)
	require.True(t, ok)
	require.NotEqual(t, idxA, idxB)

	require.Equal(t, []*flowpb.Endpoint{a, b}, d.List())

	var got []*observerpb.ConntrackStatsEndpoint
	for ep := range d.Endpoints() {
		got = append(got, ep)
	}
	require.Len(t, got, 2)
	require.EqualValues(t, 0, got[0].GetIndex())
	require.Same(t, a, got[0].GetEndpoint())
	require.EqualValues(t, 1, got[1].GetIndex())
	require.Same(t, b, got[1].GetEndpoint())
}

func TestWrap(t *testing.T) {
	require.Nil(t, Wrap(nil))
	idx := uint32(7)
	require.EqualValues(t, 7, Wrap(&idx).GetValue())
}
