// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package conntrack

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	observerpb "github.com/cilium/cilium/api/v1/observer"
)

// entryFilter matches ConntrackEntry values against a *observerpb.ConntrackFilter.
// A nil entryFilter matches every entry.
type entryFilter struct {
	sourceAddrs, destAddrs       []string
	sourcePrefixes, destPrefixes []netip.Prefix
	sourcePorts, destPorts       []uint32
	protocols                    []uint32
	directions                   []flowpb.TrafficDirection
}

// newEntryFilter validates f and builds a matcher for it. It returns a nil
// entryFilter, without error, if f is nil or every one of its fields is
// unset, so callers can skip filtering entirely in the common case.
func newEntryFilter(f *observerpb.ConntrackFilter) (*entryFilter, error) {
	if f == nil {
		return nil, nil
	}

	ef := &entryFilter{
		sourcePorts: f.GetSourcePort(),
		destPorts:   f.GetDestinationPort(),
		protocols:   f.GetProtocol(),
		directions:  f.GetDirection(),
	}

	var err error
	if ef.sourceAddrs, ef.sourcePrefixes, err = splitIPFilter(f.GetSourceIp()); err != nil {
		return nil, fmt.Errorf("invalid source_ip filter: %w", err)
	}
	if ef.destAddrs, ef.destPrefixes, err = splitIPFilter(f.GetDestinationIp()); err != nil {
		return nil, fmt.Errorf("invalid destination_ip filter: %w", err)
	}

	if ef.isEmpty() {
		return nil, nil
	}
	return ef, nil
}

func (ef *entryFilter) isEmpty() bool {
	return len(ef.sourceAddrs) == 0 && len(ef.sourcePrefixes) == 0 &&
		len(ef.destAddrs) == 0 && len(ef.destPrefixes) == 0 &&
		len(ef.sourcePorts) == 0 && len(ef.destPorts) == 0 &&
		len(ef.protocols) == 0 && len(ef.directions) == 0
}

// splitIPFilter splits ips into exact addresses and CIDR prefixes: each value
// is either an exact address (e.g. "10.0.0.1") or a CIDR range
// (e.g. "10.0.0.0/24"), mirroring the convention `hubble observe`'s IP
// filters use.
func splitIPFilter(ips []string) (addrs []string, prefixes []netip.Prefix, err error) {
	for _, ip := range ips {
		if strings.Contains(ip, "/") {
			prefix, err := netip.ParsePrefix(ip)
			if err != nil {
				return nil, nil, fmt.Errorf("invalid CIDR %q: %w", ip, err)
			}
			prefixes = append(prefixes, prefix)
			continue
		}
		if _, err := netip.ParseAddr(ip); err != nil {
			return nil, nil, fmt.Errorf("invalid IP address %q: %w", ip, err)
		}
		addrs = append(addrs, ip)
	}
	return addrs, prefixes, nil
}

func matchIP(ip string, addrs []string, prefixes []netip.Prefix) bool {
	if len(addrs) == 0 && len(prefixes) == 0 {
		return true
	}
	if slices.Contains(addrs, ip) {
		return true
	}
	if len(prefixes) == 0 {
		return false
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	return slices.ContainsFunc(prefixes, func(p netip.Prefix) bool {
		return p.Contains(addr)
	})
}

// match reports whether e matches every field set on ef. A nil ef matches
// every entry.
func (ef *entryFilter) match(e *observerpb.ConntrackEntry) bool {
	if ef == nil {
		return true
	}
	if !matchIP(e.GetSourceIp(), ef.sourceAddrs, ef.sourcePrefixes) {
		return false
	}
	if !matchIP(e.GetDestinationIp(), ef.destAddrs, ef.destPrefixes) {
		return false
	}
	if len(ef.sourcePorts) > 0 && !slices.Contains(ef.sourcePorts, e.GetSourcePort()) {
		return false
	}
	if len(ef.destPorts) > 0 && !slices.Contains(ef.destPorts, e.GetDestinationPort()) {
		return false
	}
	if len(ef.protocols) > 0 && !slices.Contains(ef.protocols, e.GetProtocol()) {
		return false
	}
	if len(ef.directions) > 0 && !slices.Contains(ef.directions, e.GetDirection()) {
		return false
	}
	return true
}
