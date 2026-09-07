// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package resolver

import (
	"github.com/cilium/hive/cell"
)

// Cell provides the shared identity/endpoint/DNS/service resolvers used to
// enrich Hubble results (flow parsing, conntrack dumps, and any future map
// dump) from live agent state. Each getter is a single-purpose type built
// from only the dependency it needs, and each is a genuine Hive singleton -
// every consumer shares the same instance rather than each building its own.
var Cell = cell.Module(
	"hubble-resolver",
	"Provides shared identity endpoint DNS and service resolvers for Hubble",

	cell.Provide(
		NewIdentityGetter,
		NewEndpointGetter,
		NewDNSGetter,
		NewServiceGetter,
		NewIPGetter,
		NewPodMetadataGetter,
		NewLinkGetter,
		NewNodeGetter,
	),
)
