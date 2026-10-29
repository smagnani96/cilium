// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package ctstats

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"

	conntrackpb "github.com/cilium/cilium/api/v1/conntrack"
	flowpb "github.com/cilium/cilium/api/v1/flow"
)

func filterUsesResolved(f *conntrackpb.Filter) bool {
	return len(f.GetSourceEndpoint())+len(f.GetDestinationEndpoint())+len(f.GetDestinationService())+
		len(f.GetSourceNode())+len(f.GetDestinationNode()) > 0
}

type filter struct {
	srcIP, dstIP            []netip.Prefix
	srcPort, dstPort, proto []uint32
	srcEP, dstEP, dstSvc    []nsName
	srcNode, dstNode        []string
}

// nsName matches "[<namespace>/]<name-prefix>".
type nsName struct{ ns, prefix string }

func parseNames(names []string) []nsName {
	out := make([]nsName, len(names))
	for i, n := range names {
		if ns, prefix, ok := strings.Cut(n, "/"); ok {
			out[i] = nsName{ns, prefix}
		} else {
			out[i] = nsName{"", n}
		}
	}
	return out
}

func (f nsName) match(ns, name string) bool {
	return (f.ns == "" || f.ns == ns) && strings.HasPrefix(name, f.prefix)
}

func parsePrefixes(ips []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, len(ips))
	for i, s := range ips {
		if a, err := netip.ParseAddr(s); err == nil {
			out[i] = netip.PrefixFrom(a, a.BitLen())
			continue
		}
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("invalid IP or CIDR %q", s)
		}
		out[i] = p
	}
	return out, nil
}

// newFilter returns nil if f is nil.
func newFilter(f *conntrackpb.Filter) (*filter, error) {
	if f == nil {
		return nil, nil
	}
	srcIP, err := parsePrefixes(f.GetSourceIp())
	if err != nil {
		return nil, err
	}
	dstIP, err := parsePrefixes(f.GetDestinationIp())
	if err != nil {
		return nil, err
	}
	return &filter{
		srcIP: srcIP, dstIP: dstIP,
		srcPort: f.GetSourcePort(), dstPort: f.GetDestinationPort(), proto: f.GetProtocol(),
		srcEP: parseNames(f.GetSourceEndpoint()), dstEP: parseNames(f.GetDestinationEndpoint()),
		dstSvc:  parseNames(f.GetDestinationService()),
		srcNode: f.GetSourceNode(), dstNode: f.GetDestinationNode(),
	}, nil
}

func (f *filter) apply(v View) View {
	eps := map[uint32]*flowpb.Endpoint{}
	for ep := range v.Endpoints() {
		eps[ep.GetIndex()] = ep.GetEndpoint()
	}
	svcs := map[uint32]*flowpb.Service{}
	for svc := range v.Services() {
		svcs[svc.GetIndex()] = svc.GetService()
	}
	nodes := map[uint32]*conntrackpb.Node{}
	for n := range v.Nodes() {
		nodes[n.GetIndex()] = n.GetNode()
	}

	var entries []*conntrackpb.Entry
	for e := range v.Entries() {
		k := e.GetKey()
		if matchIP(k.GetSourceIp(), f.srcIP) && matchIP(k.GetDestinationIp(), f.dstIP) &&
			matchIn(k.GetSourcePort(), f.srcPort) && matchIn(k.GetDestinationPort(), f.dstPort) &&
			matchIn(k.GetProtocol(), f.proto) &&
			matchEndpoint(at(eps, e.SourceEndpointIndex), f.srcEP) &&
			matchEndpoint(at(eps, e.DestinationEndpointIndex), f.dstEP) &&
			matchService(at(svcs, e.DestinationServiceIndex), f.dstSvc) &&
			matchNode(at(nodes, e.SourceNodeIndex), f.srcNode) &&
			matchNode(at(nodes, e.DestinationNodeIndex), f.dstNode) {
			entries = append(entries, e)
		}
	}
	return newView(v, entries)
}

// at returns the value m holds for idx, nil if idx is unset.
func at[T any](m map[uint32]*T, idx *uint32) *T {
	if idx == nil {
		return nil
	}
	return m[*idx]
}

func matchIn(v uint32, vals []uint32) bool {
	return len(vals) == 0 || slices.Contains(vals, v)
}

func matchIP(s string, prefixes []netip.Prefix) bool {
	if len(prefixes) == 0 {
		return true
	}
	a, err := netip.ParseAddr(s)
	return err == nil && slices.ContainsFunc(prefixes, func(p netip.Prefix) bool { return p.Contains(a.Unmap()) })
}

// The following never match what is not resolved.
func matchEndpoint(ep *flowpb.Endpoint, fs []nsName) bool {
	return len(fs) == 0 || ep != nil && slices.ContainsFunc(fs, func(f nsName) bool {
		return f.match(ep.GetNamespace(), ep.GetPodName())
	})
}

func matchService(svc *flowpb.Service, fs []nsName) bool {
	return len(fs) == 0 || svc != nil && slices.ContainsFunc(fs, func(f nsName) bool {
		return f.match(svc.GetNamespace(), svc.GetName())
	})
}

func matchNode(n *conntrackpb.Node, fs []string) bool {
	return len(fs) == 0 || n != nil && slices.ContainsFunc(fs, func(f string) bool {
		return f == n.GetName() || f == n.GetCluster()+"/"+n.GetName()
	})
}
