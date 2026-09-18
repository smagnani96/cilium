// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package conntrack

import (
	"github.com/cilium/cilium/pkg/hubble/observer/conntrack/types"
	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"
)

var Cell = cell.Module(
	"hubble-ct-exporter",
	"Exports a snapshot of the node datapath conntrack maps to Hubble",

	cell.Config(defaultConntrackExporterConfig),
	cell.ProvidePrivate(newConntrackExporter),
	cell.Provide(func(c *ctExporter) types.CTSnapshotExporter { return c }),
)

var defaultConntrackExporterConfig = Config{
	EnableCTSnapshot: true,
}

type Config struct {
	EnableCTSnapshot bool `mapstructure:"hubble-enable-ct-snapshot"`
}

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.Bool("hubble-enable-ct-snapshot", def.EnableCTSnapshot, "Enable the GetConntrackSnapshot API, which exports a snapshot of the node's datapath conntrack maps to Hubble.")
}
