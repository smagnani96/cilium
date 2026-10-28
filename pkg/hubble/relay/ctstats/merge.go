// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package ctstats

import (
	"context"
	"iter"

	conntrackpb "github.com/cilium/cilium/api/v1/conntrack"
	"github.com/cilium/cilium/pkg/ctstats"
	"github.com/cilium/cilium/pkg/ctstats/ttlcache"
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
}

type Snapshot struct {
	entries      map[ctKey]*ctValue
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
				State: &conntrackpb.State{Alive: v.alive},
			}
			if !yield(e) {
				return
			}
		}
	}
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

func NewStatsExporter(fetch func(ctx context.Context) (<-chan *conntrackpb.GetStatsResponse, func() error), ttl time.Duration) *StatsExporter {
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
func mergeConntrackResponses(responses <-chan *conntrackpb.GetStatsResponse) *Snapshot {
	snap := &Snapshot{
		entries:      make(map[ctKey]*ctValue),
		nodeStatuses: make([]*conntrackpb.GetStatsResponse, 0),
	}

	for resp := range responses {
		if ns := resp.GetNodeStatus(); ns != nil {
			snap.nodeStatuses = append(snap.nodeStatuses, resp)
			continue
		}
		if e := resp.GetEntry(); e != nil {
			aggregateCtEntry(snap.entries, e)
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
func aggregateCtEntry(
	entries map[ctKey]*ctValue,
	val *conntrackpb.Entry,
) {
	rawFlags := val.GetKey().GetFlags()
	k := keyOf(val.GetKey())
	e, ok := entries[k]
	if !ok {
		entries[k] = valueOf(val)
		return
	}

	if e.flags&ctstats.TupleFlagIn == 0 && rawFlags&ctstats.TupleFlagIn != 0 {
		// e is already the canonical view of this connection.
		return
	}
	if e.flags&ctstats.TupleFlagIn != 0 && rawFlags&ctstats.TupleFlagIn == 0 {
		// val is the canonical view instead.
		entries[k] = valueOf(val)
		return
	}

	e.alive = e.alive || val.GetState().GetAlive()
	e.Max(valueFromProto(val.GetValue()))
}

func valueFromProto(v *conntrackpb.Value) ctstats.Value {
	return ctstats.Value{
		RxPackets: v.GetRxPackets(),
		TxPackets: v.GetTxPackets(),
		RxBytes:   v.GetRxBytes(),
		TxBytes:   v.GetTxBytes(),
	}
}
