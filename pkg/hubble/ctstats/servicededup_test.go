// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package ctstats

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	flowpb "github.com/cilium/cilium/api/v1/flow"
)

func TestServiceDedup(t *testing.T) {
	d := NewServiceDedup()

	_, ok := d.Index(nil)
	require.False(t, ok)

	web := &flowpb.Service{Namespace: "default", Name: "web"}
	idx, ok := d.Index(web)
	require.True(t, ok)
	require.EqualValues(t, 0, idx)

	again, _ := d.Index(&flowpb.Service{Namespace: "default", Name: "web"})
	require.Equal(t, idx, again)

	other, _ := d.Index(&flowpb.Service{Namespace: "other", Name: "web"})
	require.EqualValues(t, 1, other)

	got := slices.Collect(IndexedServices(d))
	require.Len(t, got, 2)
	require.Same(t, web, got[0].GetService())
	require.EqualValues(t, 1, got[1].GetIndex())
}
