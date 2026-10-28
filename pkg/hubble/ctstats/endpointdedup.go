// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package ctstats

import (
	"iter"

	conntrackpb "github.com/cilium/cilium/api/v1/conntrack"
	flowpb "github.com/cilium/cilium/api/v1/flow"
)

type EndpointDedup = Dedup[endpointKey, *flowpb.Endpoint]

func IndexedEndpoints(d *EndpointDedup) iter.Seq[*conntrackpb.IndexedEndpoint] {
	return func(yield func(*conntrackpb.IndexedEndpoint) bool) {
		for i, ep := range d.All() {
			if !yield(&conntrackpb.IndexedEndpoint{Index: i, Endpoint: ep}) {
				return
			}
		}
	}
}

// NewEndpointDedup returns a Dedup of resolved flow.Endpoints.
//
// Two endpoints are the same if they belong to the same pod (cluster,
// namespace, name and UID) or, without a pod, to the same cluster and identity.
// The endpoint ID and the identity of a pod are ignored, as they may change or
// be known only by its node.
func NewEndpointDedup() *EndpointDedup {
	return newDedup(keyOf)
}

type endpointKey struct {
	clusterName, namespace, podName, podUID string
	identity                                uint32
}

func keyOf(ep *flowpb.Endpoint) endpointKey {
	if pod := ep.GetPodName(); pod != "" {
		return endpointKey{clusterName: ep.GetClusterName(), namespace: ep.GetNamespace(), podName: pod, podUID: ep.GetPodUid()}
	}
	return endpointKey{clusterName: ep.GetClusterName(), identity: ep.GetIdentity()}
}
