// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package types

import (
	"context"
	"iter"

	observerpb "github.com/cilium/cilium/api/v1/observer"
)

// Stats is the result of a single walk of the datapath conntrack maps.
type Stats interface {
	Entries() iter.Seq[*observerpb.ConntrackStatsEntry]
}

// CTStatsExporter defines the interface for exporting conntrack stats.
type CTStatsExporter interface {
	Enabled() bool
	GetConntrackStats(ctx context.Context) (Stats, error)
}
