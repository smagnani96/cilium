// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package ctstats

import (
	"maps"
	"testing"

	"github.com/stretchr/testify/require"

	flowpb "github.com/cilium/cilium/api/v1/flow"
)

func TestEndpointDedup(t *testing.T) {
	d := NewEndpointDedup()

	_, ok := d.Index(nil)
	require.False(t, ok)

	web := &flowpb.Endpoint{ID: 1, Identity: 10, Namespace: "default", PodName: "web", PodUid: "web-uid"}
	idx, ok := d.Index(web)
	require.True(t, ok)
	require.EqualValues(t, 0, idx)

	// Same pod, different endpoint ID and identity.
	again, ok := d.Index(&flowpb.Endpoint{ID: 2, Identity: 11, Namespace: "default", PodName: "web", PodUid: "web-uid"})
	require.True(t, ok)
	require.Equal(t, idx, again)

	// Same name, different pod.
	recreated, _ := d.Index(&flowpb.Endpoint{Namespace: "default", PodName: "web", PodUid: "other-uid"})
	require.EqualValues(t, 1, recreated)

	// Without a pod, the identity tells endpoints apart.
	world, _ := d.Index(&flowpb.Endpoint{Identity: 2})
	host, _ := d.Index(&flowpb.Endpoint{Identity: 1})
	worldAgain, _ := d.Index(&flowpb.Endpoint{Identity: 2})
	require.NotEqual(t, world, host)
	require.Equal(t, world, worldAgain)

	all := maps.Collect(d.All())
	require.Len(t, all, 4)
	require.Same(t, web, all[0])
}
