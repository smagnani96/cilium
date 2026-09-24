// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package conntrack

import (
	"context"
	"iter"
	"sync/atomic"
	"time"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	observerpb "github.com/cilium/cilium/api/v1/observer"
	hubbleconntrack "github.com/cilium/cilium/pkg/hubble/observer/conntrack"
	"golang.org/x/sync/singleflight"
)

// tupleFIn mirrors ctmap.TUPLE_F_IN (pkg/maps/ctmap).
const tupleFIn = 1

// ctKey identifies a logical connection across nodes. As with
// pkg/hubble/observer/conntrack's mergeKey, a single connection between
// two Cilium-managed endpoints on different nodes produces one
// TUPLE_F_OUT-flagged conntrack entry on the sending endpoint's node and one
// TUPLE_F_IN-flagged entry (RX/TX swapped, same packets, not additional
// traffic) on the receiving endpoint's node; masking the bit here lets
// aggregateCtEntry recognize and merge that pair instead of reporting
// the connection twice.
type ctKey struct {
	srcIP, dstIP     string
	srcPort, dstPort uint32
	protocol         uint32
	flags            uint32
}

// ctValue represents the aggregated value of a conntrack stats entry.
type ctValue struct {
	rxPackets, txPackets uint64
	rxBytes, txBytes     uint64
	// flags holds the real (unmasked) flags of whichever entry is currently
	// canonical for this key, for display purposes; see aggregateCtEntry.
	flags uint32
	// srcEndpointIdx/dstEndpointIdx index into the ctStats-wide
	// EndpointDedup this value's connection was aggregated into, once a
	// peer manages to resolve the corresponding Endpoint. See aggregateCtEntry.
	srcEndpointIdx, dstEndpointIdx *uint32
}

// ctStats holds the aggregated conntrack stats for a cluster.
type ctStats struct {
	entries      map[ctKey]*ctValue
	endpoints    *hubbleconntrack.EndpointDedup
	nodeStatuses []*observerpb.GetConntrackStatsResponse
	computedAt   time.Time
}

func (c *ctStats) Entries() iter.Seq[*observerpb.ConntrackStatsEntry] {
	return func(yield func(*observerpb.ConntrackStatsEntry) bool) {
		for k, v := range c.entries {
			e := &observerpb.ConntrackStatsEntry{
				Key: &observerpb.ConntrackStatsKey{
					SourceIp:        k.srcIP,
					DestinationIp:   k.dstIP,
					SourcePort:      k.srcPort,
					DestinationPort: k.dstPort,
					Protocol:        k.protocol,
					Flags:           v.flags,
				},
				Value: &observerpb.ConntrackStatsValue{
					RxPackets: v.rxPackets,
					TxPackets: v.txPackets,
					RxBytes:   v.rxBytes,
					TxBytes:   v.txBytes,
				},
				SourceEndpointIndex:      hubbleconntrack.Wrap(v.srcEndpointIdx),
				DestinationEndpointIndex: hubbleconntrack.Wrap(v.dstEndpointIdx),
			}
			if !yield(e) {
				return
			}
		}
	}
}

func (c *ctStats) Endpoints() iter.Seq[*observerpb.ConntrackStatsEndpoint] {
	if c.endpoints == nil {
		return func(func(*observerpb.ConntrackStatsEndpoint) bool) {}
	}
	return c.endpoints.Endpoints()
}

func (c *ctStats) NodeStatuses() []*observerpb.GetConntrackStatsResponse {
	return c.nodeStatuses
}

// ctStatsExporter is responsible for exporting conntrack stats retrieved from multiple nodes.
type ctStatsExporter struct {
	fetch func(ctx context.Context) (<-chan *PeerResponse, func() error)

	stats    atomic.Pointer[ctStats]
	refresh  singleflight.Group
	cacheTTL time.Duration
}

func newCTStatsExporter(cacheTTL time.Duration, fetch func(ctx context.Context) (<-chan *PeerResponse, func() error)) *ctStatsExporter {
	return &ctStatsExporter{fetch: fetch, cacheTTL: cacheTTL}
}

// GetConntrackStats returns the conntrack stats from all the nodes.
// Responses are aggregated as they arrive rather than buffering all responses first.
func (c *ctStatsExporter) GetConntrackStats(ctx context.Context) (Stats, error) {
	if stats := c.cachedStats(); stats != nil {
		return stats, nil
	}

	v, err, _ := c.refresh.Do("", func() (any, error) {
		// Someone else may have refreshed it between our check above and
		// winning the singleflight call.
		if stats := c.cachedStats(); stats != nil {
			return stats, nil
		}

		responses, wait := c.fetch(ctx)
		stats := mergeConntrackResponses(responses)
		if err := wait(); err != nil {
			return nil, err
		}

		// Don't cache a result where every peer failed.
		allFailed := len(responses) > 0 && len(stats.nodeStatuses) == len(responses)
		if !allFailed {
			c.stats.Store(stats)
		}
		return stats, nil
	})
	if err != nil {
		return nil, err
	}
	return v.(*ctStats), nil
}

// cachedStats returns the cached stats if it is still valid.
func (c *ctStatsExporter) cachedStats() *ctStats {
	e := c.stats.Load()
	if e != nil && time.Since(e.computedAt) < c.cacheTTL {
		return e
	}
	return nil
}

// mergeConntrackResponses consumes every peer's GetConntrackStats responses
// as they arrive on responses, merging entries for the same connection into
// a single cluster-wide entry and separating out the node_status responses
// of peers the relay could not retrieve a snapshot from. It returns no
// entries if no peer contributed any.
//
// ConntrackStatsEndpoint messages are resolved against the peer that sent them
// (peer-local indices aren't meaningful across peers, see PeerResponse) and
// re-deduplicated into the returned, cluster-wide EndpointDedup, so the same
// resolved Endpoint reported by multiple nodes (e.g. a popular destination
// pod reached from many client nodes) is still only kept once.
func mergeConntrackResponses(responses <-chan *PeerResponse) *ctStats {
	stats := &ctStats{
		entries:      make(map[ctKey]*ctValue),
		nodeStatuses: make([]*observerpb.GetConntrackStatsResponse, 0),
		endpoints:    hubbleconntrack.NewEndpointDedup(),
	}
	peerEndpoints := make(map[string]map[uint32]*flowpb.Endpoint)

	for pr := range responses {
		resp := pr.Response
		if ns := resp.GetNodeStatus(); ns != nil {
			stats.nodeStatuses = append(stats.nodeStatuses, resp)
			continue
		}
		if ce := resp.GetEndpoint(); ce != nil {
			m := peerEndpoints[pr.Peer]
			if m == nil {
				m = make(map[uint32]*flowpb.Endpoint)
				peerEndpoints[pr.Peer] = m
			}
			m[ce.GetIndex()] = ce.GetEndpoint()
			continue
		}
		if e := resp.GetEntry(); e != nil {
			src, dst := resolvePeerEndpoints(peerEndpoints[pr.Peer], e)
			aggregateCtEntry(stats.entries, e, src, dst, stats.endpoints)
		}
	}
	stats.computedAt = time.Now()

	return stats
}

// resolvePeerEndpoints resolves e's source/destination endpoint index
// against peerEndpoints, the dictionary built from the ConntrackStatsEndpoint
// messages sent so far by the peer that reported e. Either return value is
// nil if e didn't reference an index, or the peer never sent a matching
// ConntrackStatsEndpoint (which shouldn't happen for a well-behaved peer).
func resolvePeerEndpoints(peerEndpoints map[uint32]*flowpb.Endpoint, e *observerpb.ConntrackStatsEntry) (src, dst *flowpb.Endpoint) {
	if idx := e.GetSourceEndpointIndex(); idx != nil {
		src = peerEndpoints[idx.GetValue()]
	}
	if idx := e.GetDestinationEndpointIndex(); idx != nil {
		dst = peerEndpoints[idx.GetValue()]
	}
	return src, dst
}

func keyOf(k *observerpb.ConntrackStatsKey) ctKey {
	return ctKey{
		k.GetSourceIp(), k.GetDestinationIp(),
		k.GetSourcePort(), k.GetDestinationPort(),
		k.GetProtocol(),
		k.GetFlags() &^ tupleFIn,
	}
}

func valueOf(val *observerpb.ConntrackStatsEntry) *ctValue {
	return &ctValue{
		rxPackets: val.GetValue().GetRxPackets(),
		txPackets: val.GetValue().GetTxPackets(),
		rxBytes:   val.GetValue().GetRxBytes(),
		txBytes:   val.GetValue().GetTxBytes(),
		flags:     val.GetKey().GetFlags(),
	}
}

// aggregateCtEntry aggregates a conntrack entry into the same connection.
//
// Two cases are handled differently:
//
//   - A TUPLE_F_IN/TUPLE_F_OUT mirror pair (see ctKey): the two entries
//     describe the same physical traffic seen from opposite ends, so the
//     mirror is dropped outright rather than merged into the canonical
//     (TUPLE_F_OUT, or whichever side arrived first) entry's counters.
//   - Repeated observations of the same view (e.g. retries, or the same
//     entry reported more than once): counters are reconciled by keeping
//     the maximum value observed, not by summing them.
//
// src/dst are the source/destination Endpoint this particular val already
// had resolved by its own peer, if any; whichever peer resolves them first
// wins; once set on the aggregated entry, they are never overwritten by a
// later, potentially unresolved, observation of the same connection.
func aggregateCtEntry(
	entries map[ctKey]*ctValue,
	val *observerpb.ConntrackStatsEntry,
	src, dst *flowpb.Endpoint,
	dedup *hubbleconntrack.EndpointDedup,
) {
	rawFlags := val.GetKey().GetFlags()
	k := keyOf(val.GetKey())
	e, ok := entries[k]
	if !ok {
		e = valueOf(val)
		entries[k] = e
		fillEndpointIndices(e, src, dst, dedup)
		return
	}

	if e.flags&tupleFIn == 0 && rawFlags&tupleFIn != 0 {
		// e is already the canonical view of this connection.
		fillEndpointIndices(e, src, dst, dedup)
		return
	}
	if e.flags&tupleFIn != 0 && rawFlags&tupleFIn == 0 {
		// val is the canonical view instead. Keep data if already resolved.
		newEntry := valueOf(val)
		newEntry.srcEndpointIdx, newEntry.dstEndpointIdx = e.srcEndpointIdx, e.dstEndpointIdx
		entries[k] = newEntry
		fillEndpointIndices(newEntry, src, dst, dedup)
		return
	}

	if x := val.GetValue().GetRxPackets(); x > e.rxPackets {
		e.rxPackets = x
	}
	if x := val.GetValue().GetRxBytes(); x > e.rxBytes {
		e.rxBytes = x
	}
	if x := val.GetValue().GetTxPackets(); x > e.txPackets {
		e.txPackets = x
	}
	if x := val.GetValue().GetTxBytes(); x > e.txBytes {
		e.txBytes = x
	}
	fillEndpointIndices(e, src, dst, dedup)
}

// fillEndpointIndices assigns e's source/destination endpoint index from
// src/dst, but only if not already set: the first peer to resolve a given
// connection's endpoint wins, and is never overwritten by a later,
// potentially unresolved, observation of the same connection.
func fillEndpointIndices(e *ctValue, src, dst *flowpb.Endpoint, dedup *hubbleconntrack.EndpointDedup) {
	if e.srcEndpointIdx == nil {
		if idx, ok := dedup.Index(src); ok {
			e.srcEndpointIdx = &idx
		}
	}
	if e.dstEndpointIdx == nil {
		if idx, ok := dedup.Index(dst); ok {
			e.dstEndpointIdx = &idx
		}
	}
}
