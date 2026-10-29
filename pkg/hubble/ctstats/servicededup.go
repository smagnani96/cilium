// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package ctstats

import (
	"iter"

	conntrackpb "github.com/cilium/cilium/api/v1/conntrack"
	flowpb "github.com/cilium/cilium/api/v1/flow"
)

type ServiceDedup = Dedup[serviceKey, *flowpb.Service]

type serviceKey struct {
	namespace, name string
}

// NewServiceDedup returns a Dedup of resolved flow.Services, which are the
// same if they have the same namespace and name.
func NewServiceDedup() *ServiceDedup {
	return newDedup(func(svc *flowpb.Service) serviceKey {
		return serviceKey{namespace: svc.GetNamespace(), name: svc.GetName()}
	})
}

func IndexedServices(d *ServiceDedup) iter.Seq[*conntrackpb.IndexedService] {
	return func(yield func(*conntrackpb.IndexedService) bool) {
		for i, svc := range d.All() {
			if !yield(&conntrackpb.IndexedService{Index: i, Service: svc}) {
				return
			}
		}
	}
}
