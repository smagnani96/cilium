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
	Endpoints() iter.Seq[*observerpb.ConntrackStatsEndpoint]
	Nodes() iter.Seq[*observerpb.ConntrackStatsNode]
	NodeStatuses() []*observerpb.GetConntrackStatsResponse
}

// CTStatsExporter defines the interface for exporting conntrack stats.
type CTStatsExporter interface {
	GetConntrackStats(ctx context.Context) (Stats, error)
}

// PeerResponse pairs a GetConntrackStatsResponse with the name of the peer
// that sent it. Peer identity is needed because a ConntrackStatsEntry's
// source/destination endpoint index is only meaningful within the response
// stream of the peer that assigned it: two different peers may each use
// index 0 for entirely different resolved Endpoints.
type PeerResponse struct {
	Peer     string
	Response *observerpb.GetConntrackStatsResponse
}

func NewCTStatsExporter(cacheTTL time.Duration, fetch func(ctx context.Context) (<-chan *PeerResponse, func() error)) CTStatsExporter {
	return newCTStatsExporter(cacheTTL, fetch)
}
