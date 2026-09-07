// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package mapexporter

import (
	"context"

	"github.com/cilium/hive/cell"

	observerpb "github.com/cilium/cilium/api/v1/observer"
	"github.com/cilium/cilium/pkg/hubble/mapexporter/conntrack"
)

var Cell = cell.Module(
	"hubble-mapexporter",
	"Exports on-demand datapath maps to Hubble",

	conntrack.Cell,

	cell.Provide(newExporter),
)

type Exporter interface {
	GetConntrackEntries(ctx context.Context, req *observerpb.GetConntrackEntriesRequest, send func(*observerpb.ConntrackEntry) bool) error
}

type exporter struct {
	ctExporter *conntrack.ConntrackExporter
}

func newExporter(ctExporter *conntrack.ConntrackExporter) Exporter {
	return &exporter{
		ctExporter: ctExporter,
	}
}

func (e *exporter) GetConntrackEntries(ctx context.Context, req *observerpb.GetConntrackEntriesRequest, send func(*observerpb.ConntrackEntry) bool) error {
	return e.ctExporter.GetConntrackEntries(ctx, req, send)
}
