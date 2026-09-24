// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package conntrack

import (
	"time"

	"github.com/cilium/cilium/pkg/hubble/observer/conntrack/types"
	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"
)

var Cell = cell.Module(
	"hubble-ct-stats-exporter",
	"Exports Conntrack stats from the datapath to Hubble",

	cell.Config(defaultConntrackExporterConfig),
	cell.ProvidePrivate(newCTStatsExporter),
	cell.Provide(func(c *ctStatsExporter) types.CTStatsExporter { return c }),
)

var defaultConntrackExporterConfig = Config{
	ConntrackCacheTTL: 30 * time.Second,
}

type Config struct {
	ConntrackCacheTTL time.Duration `mapstructure:"hubble-ct-stats-cache-ttl"`
}

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.Duration("hubble-ct-stats-cache-ttl", def.ConntrackCacheTTL, "Duration for which the conntrack stats are cached.")
}
