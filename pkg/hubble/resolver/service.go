// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package resolver

import (
	"log/slog"
	"net/netip"

	"github.com/cilium/statedb"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/hubble/resolver/types"
	"github.com/cilium/cilium/pkg/loadbalancer"
	lbmaps "github.com/cilium/cilium/pkg/loadbalancer/maps"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/time"
)

// ServiceGetter implements getters.ServiceGetter using Cilium's
// load-balancing state. It's the canonical implementation shared by every
// Hubble RPC that needs service resolution (flow parsing, conntrack dumps).
type ServiceGetter struct {
	db        *statedb.DB
	frontends statedb.Table[*loadbalancer.Frontend]
	log       *slog.Logger

	lbmaps               lbmaps.LBMaps
	backendsMu           lock.Mutex
	backends4, backends6 map[loadbalancer.BackendID]netip.Addr
	backendsRefreshedAt  time.Time
}

func NewServiceGetter(db *statedb.DB, frontends statedb.Table[*loadbalancer.Frontend], lbmaps lbmaps.LBMaps, log *slog.Logger) types.ServiceGetter {
	return &ServiceGetter{db: db, frontends: frontends, lbmaps: lbmaps, log: log}
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

func (g *ServiceGetter) GetServiceByRevNatIndex(revNatIndex uint32) *flowpb.Service {
	txn := g.db.ReadTxn()
	fe, found := loadbalancer.LookupFrontendByID(txn, g.frontends, loadbalancer.ServiceID(revNatIndex))
	if !found {
		return nil
	}
	return &flowpb.Service{
		Namespace: fe.ServiceName.Namespace(),
		Name:      fe.ServiceName.Name(),
	}
}

// GetBackendAddrByID resolves backendID to the real address of the specific
// backend Pod this connection was load-balanced to. There's no StateDB path
// for this, so it's served from a BPF lookup.
func (g *ServiceGetter) GetBackendAddrByID(backendID uint32, isIPv6 bool) (netip.Addr, bool) {
	if backendID == 0 || g.lbmaps == nil {
		return netip.Addr{}, false
	}
	var val lbmaps.BackendValue
	var err error
	if isIPv6 {
		val, err = g.lbmaps.LookupBackend(lbmaps.NewBackend6KeyV3(loadbalancer.BackendID(backendID)))
	} else {
		val, err = g.lbmaps.LookupBackend(lbmaps.NewBackend4KeyV3(loadbalancer.BackendID(backendID)))
	}
	if err != nil {
		return netip.Addr{}, false
	}
	return val.ToHost().GetAddress().Addr(), true
}
