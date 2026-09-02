// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package resolver

import (
	"net/netip"

	"github.com/cilium/statedb"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/hubble/resolver/types"
	"github.com/cilium/cilium/pkg/loadbalancer"
)

// ServiceGetter implements getters.ServiceGetter using Cilium's
// load-balancing state. It's the canonical implementation shared by every
// Hubble RPC that needs service resolution (flow parsing, conntrack dumps).
type ServiceGetter struct {
	db        *statedb.DB
	frontends statedb.Table[*loadbalancer.Frontend]
}

func NewServiceGetter(db *statedb.DB, frontends statedb.Table[*loadbalancer.Frontend]) types.ServiceGetter {
	return &ServiceGetter{db: db, frontends: frontends}
}

// GetServiceByAddr implements getters.ServiceGetter. It looks up service by
// IP/port.
func (g *ServiceGetter) GetServiceByAddr(ip netip.Addr, port uint16) *flowpb.Service {
	if !ip.IsValid() {
		return nil
	}
	addrCluster := cmtypes.AddrClusterFrom(ip, 0)
	txn := g.db.ReadTxn()
	fe, found := loadbalancer.LookupFrontendByTuple(txn, g.frontends, addrCluster, loadbalancer.TCP, port, loadbalancer.ScopeExternal)
	if !found {
		fe, found = loadbalancer.LookupFrontendByTuple(txn, g.frontends, addrCluster, loadbalancer.UDP, port, loadbalancer.ScopeExternal)
	}
	if !found {
		return nil
	}
	return &flowpb.Service{
		Namespace: fe.ServiceName.Namespace(),
		Name:      fe.ServiceName.Name(),
	}
}
