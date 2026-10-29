// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package ctstats

import (
	"context"
	"iter"

	conntrackpb "github.com/cilium/cilium/api/v1/conntrack"
	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/ctstats"
	"github.com/cilium/cilium/pkg/ctstats/ttlcache"
	hubblectstats "github.com/cilium/cilium/pkg/hubble/ctstats"
	"github.com/cilium/cilium/pkg/time"
)

// ctKey identifies a logical connection across nodes.
type ctKey struct {
	srcIP, dstIP     string
	srcPort, dstPort uint32
	protocol         uint32
	flags            uint32
}

type ctValue struct {
	ctstats.Value
	flags uint32
	alive bool
	// srcEndpoint and dstEndpoint index into the Snapshot's endpoints, nil
	// until a peer resolves them. dstService does the same for the services.
	srcEndpoint, dstEndpoint *uint32
	dstService               *uint32
}

// PeerResponse is a response along with the name of the peer that sent it.
// The peer is needed as endpoint and service indices are only meaningful within
// the stream of the peer that assigned them.
type PeerResponse struct {
	Peer     string
	Response *conntrackpb.GetStatsResponse
}

type Snapshot struct {
	entries      map[ctKey]*ctValue
	endpoints    *hubblectstats.EndpointDedup
	services     *hubblectstats.ServiceDedup
	nodeStatuses []*conntrackpb.GetStatsResponse
}

func (c *Snapshot) Entries() iter.Seq[*conntrackpb.Entry] {
	return func(yield func(*conntrackpb.Entry) bool) {
		for k, v := range c.entries {
			e := &conntrackpb.Entry{
				Key: &conntrackpb.Key{
					SourceIp:        k.srcIP,
					DestinationIp:   k.dstIP,
					SourcePort:      k.srcPort,
					DestinationPort: k.dstPort,
					Protocol:        k.protocol,
					Flags:           v.flags,
				},
				Value: &conntrackpb.Value{
					RxPackets: v.RxPackets,
					TxPackets: v.TxPackets,
					RxBytes:   v.RxBytes,
					TxBytes:   v.TxBytes,
				},
				State:                    &conntrackpb.State{Alive: v.alive},
				SourceEndpointIndex:      v.srcEndpoint,
				DestinationEndpointIndex: v.dstEndpoint,
				DestinationServiceIndex:  v.dstService,
			}
			if !yield(e) {
				return
			}
		}
	}
}

func (c *Snapshot) Endpoints() iter.Seq[*conntrackpb.IndexedEndpoint] {
	return hubblectstats.IndexedEndpoints(c.endpoints)
}

func (c *Snapshot) Services() iter.Seq[*conntrackpb.IndexedService] {
	return hubblectstats.IndexedServices(c.services)
}

func (c *Snapshot) NodeStatuses() iter.Seq[*conntrackpb.GetStatsResponse] {
	return func(yield func(*conntrackpb.GetStatsResponse) bool) {
		for _, ns := range c.nodeStatuses {
			if !yield(ns) {
				return
			}
		}
	}
}

// fetchTimeout bounds a cluster-wide fetch, which is shared by its callers.
const fetchTimeout = time.Minute

// StatsExporter is responsible for exporting conntrack stats retrieved from
// multiple nodes. The merged Snapshot is cached for the ttl, so that concurrent
// and subsequent clients are served without fanning out to the peers again.
type StatsExporter struct {
	snapshot *ttlcache.Cache[*Snapshot]
}

func NewStatsExporter(fetch func(ctx context.Context) (<-chan *PeerResponse, func() error), ttl time.Duration) *StatsExporter {
	return &StatsExporter{
		snapshot: ttlcache.New(ttl, func(ctx context.Context) (*Snapshot, error) {
			// Detach from the caller's cancellation, as the result is shared.
			ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), fetchTimeout)
			defer cancel()

			responses, wait := fetch(ctx)
			snap := mergeConntrackResponses(responses)
			if err := wait(); err != nil {
				return nil, err
			}
			return snap, nil
		}),
	}
}

// Snapshot returns the conntrack stats from all the nodes, refreshing them
// first if the cached ones are older than the ttl. The returned Snapshot is
// shared and must not be modified.
func (c *StatsExporter) Snapshot(ctx context.Context) (*Snapshot, error) {
	snap, err := c.snapshot.Get(ctx)
	if err != nil {
		return nil, err
	}
	return snap, nil
}

// mergeConntrackResponses merges the responses of the peers into a Snapshot with
// an entry per connection, setting the node statuses aside.
//
// Endpoint and service indices are local to the stream of the peer that
// assigned them, so they are resolved against that peer's endpoints and
// services and re-indexed in the cluster-wide Snapshot, where each distinct
// endpoint and service is kept only once.
func mergeConntrackResponses(responses <-chan *PeerResponse) *Snapshot {
	snap := &Snapshot{
		entries:      make(map[ctKey]*ctValue),
		endpoints:    hubblectstats.NewEndpointDedup(),
		services:     hubblectstats.NewServiceDedup(),
		nodeStatuses: make([]*conntrackpb.GetStatsResponse, 0),
	}
	peerEndpoints := make(map[string]map[uint32]*flowpb.Endpoint)
	peerServices := make(map[string]map[uint32]*flowpb.Service)

	for pr := range responses {
		resp := pr.Response
		if ns := resp.GetNodeStatus(); ns != nil {
			snap.nodeStatuses = append(snap.nodeStatuses, resp)
			continue
		}
		if ep := resp.GetEndpoint(); ep != nil {
			if peerEndpoints[pr.Peer] == nil {
				peerEndpoints[pr.Peer] = make(map[uint32]*flowpb.Endpoint)
			}
			peerEndpoints[pr.Peer][ep.GetIndex()] = ep.GetEndpoint()
			continue
		}
		if svc := resp.GetService(); svc != nil {
			if peerServices[pr.Peer] == nil {
				peerServices[pr.Peer] = make(map[uint32]*flowpb.Service)
			}
			peerServices[pr.Peer][svc.GetIndex()] = svc.GetService()
			continue
		}
		if e := resp.GetEntry(); e != nil {
			eps, svcs := peerEndpoints[pr.Peer], peerServices[pr.Peer]
			var res resolved
			if idx := e.SourceEndpointIndex; idx != nil {
				res.srcEndpoint = eps[*idx]
			}
			if idx := e.DestinationEndpointIndex; idx != nil {
				res.dstEndpoint = eps[*idx]
			}
			if idx := e.DestinationServiceIndex; idx != nil {
				res.dstService = svcs[*idx]
			}
			aggregateCtEntry(snap.entries, e, res, snap.endpoints, snap.services)
		}
	}

	return snap
}

func keyOf(k *conntrackpb.Key) ctKey {
	return ctKey{
		k.GetSourceIp(), k.GetDestinationIp(),
		k.GetSourcePort(), k.GetDestinationPort(),
		k.GetProtocol(),
		k.GetFlags() &^ ctstats.TupleFlagIn,
	}
}

func valueOf(val *conntrackpb.Entry) *ctValue {
	return &ctValue{
		Value: valueFromProto(val.GetValue()),
		flags: val.GetKey().GetFlags(),
		alive: val.GetState().GetAlive(),
	}
}

// aggregateCtEntry merges a conntrack entry into the one of its connection. The
// TUPLE_F_IN mirror is dropped in favour of the canonical entry, while repeated
// observations keep the maximum counters.
//
// res holds the endpoints and services val's peer resolved, if any. The first
// resolution of a connection wins: it is kept even if the view it was
// reported with is replaced, and a later unresolved observation never clears it.
func aggregateCtEntry(
	entries map[ctKey]*ctValue,
	val *conntrackpb.Entry,
	res resolved,
	endpoints *hubblectstats.EndpointDedup,
	services *hubblectstats.ServiceDedup,
) {
	rawFlags := val.GetKey().GetFlags()
	k := keyOf(val.GetKey())
	e, ok := entries[k]
	switch {
	case !ok:
		e = valueOf(val)
		entries[k] = e
	case e.flags&ctstats.TupleFlagIn == 0 && rawFlags&ctstats.TupleFlagIn != 0:
		// e is already the canonical view of this connection.
	case e.flags&ctstats.TupleFlagIn != 0 && rawFlags&ctstats.TupleFlagIn == 0:
		// val is the canonical view instead.
		canonical := valueOf(val)
		canonical.srcEndpoint, canonical.dstEndpoint = e.srcEndpoint, e.dstEndpoint
		canonical.dstService = e.dstService
		entries[k] = canonical
		e = canonical
	default:
		e.alive = e.alive || val.GetState().GetAlive()
		e.Max(valueFromProto(val.GetValue()))
	}

	if e.srcEndpoint == nil {
		e.srcEndpoint = indexOf(endpoints, res.srcEndpoint)
	}
	if e.dstEndpoint == nil {
		e.dstEndpoint = indexOf(endpoints, res.dstEndpoint)
	}
	if e.dstService == nil {
		e.dstService = indexOf(services, res.dstService)
	}
}

// resolved holds the endpoints and services of the two sides of an entry.
type resolved struct {
	srcEndpoint, dstEndpoint *flowpb.Endpoint
	dstService               *flowpb.Service
}

// indexOf returns the index of v in dedup, nil if v is nil.
func indexOf[K, V comparable](dedup *hubblectstats.Dedup[K, V], v V) *uint32 {
	idx, ok := dedup.Index(v)
	if !ok {
		return nil
	}
	return &idx
}

func valueFromProto(v *conntrackpb.Value) ctstats.Value {
	return ctstats.Value{
		RxPackets: v.GetRxPackets(),
		TxPackets: v.GetTxPackets(),
		RxBytes:   v.GetRxBytes(),
		TxBytes:   v.GetTxBytes(),
	}
}
