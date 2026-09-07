// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package conntrack

import (
	"time"

	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"
)

var Cell = cell.Module(
	"hubble-mapexporter-conntrack",
	"Exports on-demand datapath conntrack maps to Hubble",

	cell.Config(defaultConntrackExporterConfig),
	cell.Provide(newConntrackExporter),
)

var defaultConntrackExporterConfig = Config{
	EnableConntrack:    true,
	ConntrackRateLimit: 30 * time.Second,
}

type Config struct {
	// Enable exporting of the node's datapath conntrack maps on demand.
	EnableConntrack bool `mapstructure:"hubble-enable-conntrack"`
	// ConntrackRateLimit specifies the rate limit for GetConntrackEntries API calls.
	ConntrackRateLimit time.Duration `mapstructure:"hubble-conntrack-rate-limit"`
}

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.Bool("hubble-enable-conntrack", def.EnableConntrack, "Enable the GetConntrackEntries API, which dumps the node's datapath conntrack maps on demand.")
	flags.Duration("hubble-conntrack-rate-limit", def.ConntrackRateLimit, "Rate limit for GetConntrackEntries API calls, in requests per second. 0 means no rate limit.")
}
