// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package conntrack

import (
	"context"

	observerpb "github.com/cilium/cilium/api/v1/observer"
	"github.com/cilium/cilium/pkg/time"
)

// Snapshot is the result of a single walk of the datapath conntrack maps.
type Snapshot struct {
	Entries      []*observerpb.ConntrackEntry
	ComputedAt   time.Time
	NodeStatuses []*observerpb.GetConntrackSnapshotResponse
}

// CTExporter defines the interface for exporting conntrack snapshots.
type CTExporter interface {
	GetConntrackSnapshot(ctx context.Context) (*Snapshot, error)
}

// NewCTExporter creates a new CTExporter instance using the provided fetch function.
func NewCTExporter(fetch func(ctx context.Context) ([]*observerpb.GetConntrackSnapshotResponse, error)) CTExporter {
	return newCTExporter(fetch)
}
