// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package types

import (
	"context"
	"time"

	observerpb "github.com/cilium/cilium/api/v1/observer"
)

// Snapshot is the result of a single walk of the datapath conntrack maps.
type Snapshot struct {
	Entries    []*observerpb.ConntrackEntry
	ComputedAt time.Time
}

// CTSnapshotExporter defines the interface for exporting conntrack snapshots.
type CTSnapshotExporter interface {
	GetConntrackSnapshot(ctx context.Context) (*Snapshot, error)
}
