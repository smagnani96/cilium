// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package conntrack

import (
	"iter"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	observerpb "github.com/cilium/cilium/api/v1/observer"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// Wrap converts an EndpointDedup index into the google.protobuf.UInt32Value
// used by ConntrackStatsEntry.source_endpoint_index/destination_endpoint_index,
// so an unset index (nil) round-trips to an unset field rather than to the
// ambiguous zero value.
func Wrap(idx *uint32) *wrapperspb.UInt32Value {
	if idx == nil {
		return nil
	}
	return wrapperspb.UInt32(*idx)
}

// EndpointDedup assigns a stable index to each distinct resolved
// source/destination flow.Endpoint referenced by ConntrackStatsEntry messages,
// so a GetConntrackStats response stream can carry one ConntrackStatsEndpoint
// per distinct value instead of repeating the same Endpoint on every entry
// that shares the same source and/or destination.
//
// Two Endpoints are considered the same value if they resolve to the same
// pod (cluster, namespace, pod name and pod UID all equal), or, when
// there's no pod (a reserved identity, a CIDR/world group, ...), the same
// cluster and security identity. A pod's Cilium-local endpoint ID and
// security identity are deliberately excluded from that comparison even
// though flow.Endpoint carries them: both can change over the pod's
// lifetime without it being a different pod (its endpoint regenerating
// with a new ID, or a label change reallocating its identity), and the very
// same pod can independently resolve with different values for them
// depending on the vantage point — e.g. locally, where its Cilium endpoint
// ID is known, versus from another node relying on ipcache-derived
// metadata, where it isn't (see resolver.EndpointGetter.ResolveEndpoint).
// Treating those as distinct values would under-deduplicate: the same real
// pod would appear as two separate ConntrackStatsEndpoint entries, and,
// downstream, group into two separate rows when aggregating by endpoint.
// Labels and workloads aren't compared either, as they are derived
// deterministically from the fields above by the resolver.
type EndpointDedup struct {
	byKey map[endpointKey]uint32
	list  []*flowpb.Endpoint
}

func NewEndpointDedup() *EndpointDedup {
	return &EndpointDedup{byKey: make(map[endpointKey]uint32)}
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

// Index returns the index ep is assigned in the dedup table, allocating a
// new one the first time this endpoint's value is seen. ok is false if ep
// is nil, in which case idx is meaningless.
func (d *EndpointDedup) Index(ep *flowpb.Endpoint) (idx uint32, ok bool) {
	if ep == nil {
		return 0, false
	}
	k := keyOf(ep)
	if idx, ok := d.byKey[k]; ok {
		return idx, true
	}
	idx = uint32(len(d.list))
	d.byKey[k] = idx
	d.list = append(d.list, ep)
	return idx, true
}

func (d *EndpointDedup) List() []*flowpb.Endpoint {
	return d.list
}

func (d *EndpointDedup) Endpoints() iter.Seq[*observerpb.ConntrackStatsEndpoint] {
	return func(yield func(*observerpb.ConntrackStatsEndpoint) bool) {
		for i, ep := range d.list {
			if !yield(&observerpb.ConntrackStatsEndpoint{Index: uint32(i), Endpoint: ep}) {
				return
			}
		}
	}
}
