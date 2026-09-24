// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package conntrack

import (
	"github.com/cilium/cilium/pkg/hubble/observer/conntrack/types"
	"github.com/cilium/hive/cell"
)

var Cell = cell.Module(
	"hubble-ct-stats-exporter",
	"Exports Conntrack stats from the datapath to Hubble",

	cell.ProvidePrivate(newCTStatsExporter),
	cell.Provide(func(c *ctStatsExporter) types.CTStatsExporter { return c }),
)
