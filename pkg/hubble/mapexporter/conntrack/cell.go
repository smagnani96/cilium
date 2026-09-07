// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package conntrack

import (
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
	EnableConntrack: true,
}

type Config struct {
	// Enable exporting of the node's datapath conntrack maps on demand.
	EnableConntrack bool `mapstructure:"hubble-enable-conntrack"`
}

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.Bool("hubble-enable-conntrack", def.EnableConntrack, "Enable the GetConntrackEntries API, which dumps the node's datapath conntrack maps on demand.")
}
