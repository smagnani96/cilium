// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package conntrack

import (
	"net/netip"
	"time"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/hubble/mapexporter/common"
	resolverTypes "github.com/cilium/cilium/pkg/hubble/resolver/types"
)

type CachedEndpointResolver struct {
	epGetter resolverTypes.EndpointGetter
	cache    *common.Cache[endpointCacheKey, *flowpb.Endpoint]
}

type endpointCacheKey struct {
	addr       netip.Addr
	securityID uint32
}

func NewCachedEndpointResolver(resolver resolverTypes.EndpointGetter, size int, ttl time.Duration) *CachedEndpointResolver {
	return &CachedEndpointResolver{
		epGetter: resolver,
		cache:    common.NewCache[endpointCacheKey, *flowpb.Endpoint](size, ttl),
	}
}

func (c *CachedEndpointResolver) GetEndpointInfo(ip netip.Addr) (endpoint resolverTypes.EndpointInfo, ok bool) {
	return c.epGetter.GetEndpointInfo(ip)
}

func (c *CachedEndpointResolver) GetEndpointInfoByID(id uint16) (endpoint resolverTypes.EndpointInfo, ok bool) {
	return c.epGetter.GetEndpointInfoByID(id)
}

func (c *CachedEndpointResolver) ResolveEndpoint(ip netip.Addr, datapathSecurityIdentity uint32, context resolverTypes.DatapathContext) *flowpb.Endpoint {
	key := endpointCacheKey{addr: ip, securityID: datapathSecurityIdentity}
	return c.cache.GetOrResolve(key, func() *flowpb.Endpoint {
		return c.epGetter.ResolveEndpoint(ip, datapathSecurityIdentity, context)
	})
}

type CachedNodeGetter struct {
	nodeGetter resolverTypes.NodeGetter
	cache      *common.Cache[netip.Addr, string]
}

func NewCachedNodeGetter(resolver resolverTypes.NodeGetter, size int, ttl time.Duration) *CachedNodeGetter {
	return &CachedNodeGetter{
		nodeGetter: resolver,
		cache:      common.NewCache[netip.Addr, string](size, ttl),
	}
}

func (c *CachedNodeGetter) GetNodeNameByIP(ip netip.Addr) string {
	return c.cache.GetOrResolve(ip, func() string {
		return c.nodeGetter.GetNodeNameByIP(ip)
	})
}

type cacheAddrSVC struct {
	addr netip.Addr
	port uint16
}

type CachedServiceGetter struct {
	svcGetter        resolverTypes.ServiceGetter
	cacheAddr        *common.Cache[cacheAddrSVC, *flowpb.Service]
	cacheRevNatIndex *common.Cache[uint32, *flowpb.Service]
	cacheBackendID   *common.Cache[uint32, netip.Addr]
}

func NewCachedServiceGetter(resolver resolverTypes.ServiceGetter, size int, ttl time.Duration) *CachedServiceGetter {
	return &CachedServiceGetter{
		svcGetter:        resolver,
		cacheAddr:        common.NewCache[cacheAddrSVC, *flowpb.Service](size, ttl),
		cacheRevNatIndex: common.NewCache[uint32, *flowpb.Service](size, ttl),
		cacheBackendID:   common.NewCache[uint32, netip.Addr](size, ttl),
	}
}

func (c *CachedServiceGetter) GetServiceByAddr(ip netip.Addr, port uint16) *flowpb.Service {
	key := cacheAddrSVC{addr: ip, port: port}
	return c.cacheAddr.GetOrResolve(key, func() *flowpb.Service {
		return c.svcGetter.GetServiceByAddr(ip, port)
	})
}

func (c *CachedServiceGetter) GetServiceByRevNatIndex(revNatIndex uint32) *flowpb.Service {
	return c.cacheRevNatIndex.GetOrResolve(revNatIndex, func() *flowpb.Service {
		return c.svcGetter.GetServiceByRevNatIndex(revNatIndex)
	})
}

func (c *CachedServiceGetter) GetBackendAddrByID(backendID uint32, isIPv6 bool) (netip.Addr, bool) {
	found := true
	return c.cacheBackendID.GetOrResolve(backendID, func() netip.Addr {
		addr, ok := c.svcGetter.GetBackendAddrByID(backendID, isIPv6)
		found = ok
		return addr
	}), found
}
