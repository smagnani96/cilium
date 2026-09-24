// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package conntrack

import (
	"context"
	"iter"
	"time"

	observerpb "github.com/cilium/cilium/api/v1/observer"
)

// Stats is the result of a single walk of the datapath conntrack stats maps.
type Stats interface {
	Entries() iter.Seq[*observerpb.ConntrackStatsEntry]
	NodeStatuses() []*observerpb.GetConntrackStatsResponse
}

// CTStatsExporter defines the interface for exporting conntrack stats.
type CTStatsExporter interface {
	GetConntrackStats(ctx context.Context) (Stats, error)
}

func NewCTStatsExporter(cacheTTL time.Duration, fetch func(ctx context.Context) (<-chan *observerpb.GetConntrackStatsResponse, func() error)) CTStatsExporter {
	return newCTStatsExporter(cacheTTL, fetch)
}
