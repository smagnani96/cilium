// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package conntrack

import (
	"context"

	observerpb "github.com/cilium/cilium/api/v1/observer"
	"github.com/cilium/cilium/pkg/time"
)

// ctExporter is responsible for exporting conntrack snaphots retrieved from
// multiple nodes.
type ctExporter struct {
	fetch func(ctx context.Context) ([]*observerpb.GetConntrackSnapshotResponse, error)
}

// ctAggregationKey identifies a connection across every node's own
// (already per-node deduplicated) conntrack snapshot.
type ctAggregationKey struct {
	sourceIP        string
	destinationIP   string
	destinationPort uint32
	protocol        uint32
}

// newCTExporter creates a new ctExporter instance using the provided fetch function.
func newCTExporter(fetch func(ctx context.Context) ([]*observerpb.GetConntrackSnapshotResponse, error)) *ctExporter {
	return &ctExporter{fetch: fetch}
}

// GetConntrackSnapshot returns the conntrack snapshot from all the nodes.
func (c *ctExporter) GetConntrackSnapshot(ctx context.Context) (*Snapshot, error) {
	responses, err := c.fetch(ctx)
	if err != nil {
		return nil, err
	}

	entries, nodeStatuses := mergeConntrackResponses(responses)
	return &Snapshot{
		Entries:      entries,
		ComputedAt:   time.Now(),
		NodeStatuses: nodeStatuses,
	}, nil
}

// mergeConntrackResponses merges every peer's GetConntrackSnapshot entries
// into a single cluster-wide set, separating out the node_status responses
// of peers the relay could not retrieve a snapshot from. It returns no
// entries if no peer contributed any.
func mergeConntrackResponses(responses []*observerpb.GetConntrackSnapshotResponse) ([]*observerpb.ConntrackEntry, []*observerpb.GetConntrackSnapshotResponse) {
	entries := make(map[ctAggregationKey]*observerpb.ConntrackEntry)
	var nodeStatuses []*observerpb.GetConntrackSnapshotResponse

	for _, resp := range responses {
		if ns := resp.GetNodeStatus(); ns != nil {
			nodeStatuses = append(nodeStatuses, resp)
			continue
		}
		if e := resp.GetEntry(); e != nil {
			aggregateCtEntry(entries, e)
		}
	}

	if len(entries) == 0 {
		return nil, nodeStatuses
	}

	merged := make([]*observerpb.ConntrackEntry, 0, len(entries))
	for _, e := range entries {
		merged = append(merged, e)
	}

	return merged, nodeStatuses
}

// aggregateCtEntry aggregates conntrack entry into the same connection.
// When aggregating counters, we take the maximum value observed across all peers.
// Edge cases with incongruent or not-converged data are possible and are
// not handled explicitly.
func aggregateCtEntry(
	entries map[ctAggregationKey]*observerpb.ConntrackEntry,
	val *observerpb.ConntrackEntry,
) {
	key := ctAggregationKey{
		sourceIP:        val.GetSourceIp(),
		destinationIP:   val.GetDestinationIp(),
		destinationPort: val.GetDestinationPort(),
		protocol:        val.GetProtocol(),
	}

	e, ok := entries[key]
	if !ok {
		entries[key] = val
		return
	}

	if val.Packets > e.Packets {
		e.Packets = val.Packets
	}
	if val.Bytes > e.Bytes {
		e.Bytes = val.Bytes
	}
	if val.Count > e.Count {
		e.Count = val.Count
	}
}
