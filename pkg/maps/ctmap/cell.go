// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ctmap

import (
	"context"
	"fmt"
	"log/slog"
	"slices"

	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/linux/config/defines"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/nat"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
)

// Cell provides the ctmap.Map which contains the connection tracking state.
var Cell = cell.Module(
	"ct-map",
	"eBPF map which manages connection tracking",

	cell.Config(defaultCTConfig),
	cell.Provide(newCTMaps, newCTStatsMaps),
)

type Config struct {
	// BpfCTStatsMapMax is the maximum number of entries allowed in the percpu stats map.
	BpfCTStatsMapMax int
}

var defaultCTConfig = Config{
	BpfCTStatsMapMax: 1 << 16,
}

const (
	CTStatsMapMaxName = "bpf-ct-stats-map-max"
)

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.Int(CTStatsMapMaxName, def.BpfCTStatsMapMax, "Maximum number of entries in the percpu stats maps")
}

func newCTMaps(lifecycle cell.Lifecycle, daemonConfig *option.DaemonConfig, registry *metrics.Registry, natMap4 nat.NatMap4, natMap6 nat.NatMap6) bpf.MapOut[CTMaps] {
	InitMapInfo(natMap4, natMap6)

	ctMaps := &ctMaps{}

	if daemonConfig.IPv4Enabled() {
		ctMaps.v4AnyMap = newMap(MapNameAny4Global, mapTypeIPv4AnyGlobal, WithRegistry(registry))
		ctMaps.v4TCPMap = newMap(MapNameTCP4Global, mapTypeIPv4TCPGlobal, WithRegistry(registry))
	}

	if daemonConfig.IPv6Enabled() {
		ctMaps.v6AnyMap = newMap(MapNameAny6Global, mapTypeIPv6AnyGlobal, WithRegistry(registry))
		ctMaps.v6TCPMap = newMap(MapNameTCP6Global, mapTypeIPv6TCPGlobal, WithRegistry(registry))
	}

	lifecycle.Append(cell.Hook{
		OnStart: func(context cell.HookContext) error {
			return ctMaps.init()
		},
		OnStop: func(context cell.HookContext) error {
			return ctMaps.close()
		},
	})

	return bpf.NewMapOut(CTMaps(ctMaps))
}

// CTMaps provides access to the active connection tracking BPF maps.
type CTMaps interface {
	// ActiveMaps returns a slice of global CT maps that are used, depending
	// on whether IPv4 and/or IPv6 is configured.
	ActiveMaps() []*Map
}

type ctMaps struct {
	v4AnyMap *Map
	v4TCPMap *Map
	v6AnyMap *Map
	v6TCPMap *Map
}

var _ CTMaps = (*ctMaps)(nil)

func (r *ctMaps) ActiveMaps() []*Map {
	return slices.DeleteFunc([]*Map{r.v4TCPMap, r.v4AnyMap, r.v6TCPMap, r.v6AnyMap}, func(m *Map) bool { return m == nil })
}

func (r *ctMaps) init() error {
	for _, m := range r.ActiveMaps() {
		if err := m.OpenOrCreate(); err != nil {
			return fmt.Errorf("failed to open and create %s map: %w", m.Name(), err)
		}
	}

	return nil
}

func (r *ctMaps) close() error {
	for _, m := range r.ActiveMaps() {
		if err := m.Close(); err != nil {
			return fmt.Errorf("failed to close %s map: %w", m.Name(), err)
		}
	}

	return nil
}

func newCTStatsMaps(in struct {
	cell.In

	Lifecycle    cell.Lifecycle
	Log          *slog.Logger
	DaemonConfig *option.DaemonConfig
	Config
}) (out struct {
	cell.Out

	bpf.MapOut[StatsMaps]
	defines.NodeOut
}) {
	if in.BpfCTStatsMapMax < option.LimitTableMin {
		in.Log.Warn("specified ct stats map max entries too low, using minimum value instead",
			logfields.Entries, in.BpfCTStatsMapMax,
			logfields.Minimum, option.LimitTableMin)
		in.BpfCTStatsMapMax = option.LimitTableMin
	}
	if in.BpfCTStatsMapMax > option.LimitTableMax {
		in.Log.Warn("specified ct stats map max entries too high, using maximum value instead",
			logfields.Entries, in.BpfCTStatsMapMax,
			logfields.Maximum, option.LimitTableMax)
		in.BpfCTStatsMapMax = option.LimitTableMax
	}

	var maps = &statsMaps{}
	var maxStatsEntries int
	if in.DaemonConfig.IPv4Enabled() && in.DaemonConfig.BPFConntrackAccounting {
		maps.v4StatsMap, maxStatsEntries = newStatsMap(mapTypeStats4, in.BpfCTStatsMapMax, in.Log)
		maps.maxStatsEntries = maxStatsEntries
		if int(maxStatsEntries) != in.BpfCTStatsMapMax {
			in.Log.Debug("Rounded ct stats v4 map size down to the closest multiple of the number of possible CPUs",
				logfields.Entries, maxStatsEntries)
		}
	}

	if in.DaemonConfig.IPv6Enabled() && in.DaemonConfig.BPFConntrackAccounting {
		maps.v6StatsMap, maxStatsEntries = newStatsMap(mapTypeStats6, in.BpfCTStatsMapMax, in.Log)
		maps.maxStatsEntries = maxStatsEntries
		if int(maxStatsEntries) != in.BpfCTStatsMapMax {
			in.Log.Debug("Rounded ct stats v6 map size down to the closest multiple of the number of possible CPUs",
				logfields.Entries, maxStatsEntries)
		}
	}

	out.NodeDefines = map[string]string{
		"CT_STATS_MAP_SIZE": fmt.Sprint(maxStatsEntries),
	}

	in.Lifecycle.Append(cell.Hook{
		OnStart: func(context cell.HookContext) error {
			return maps.init()
		},
		OnStop: func(context cell.HookContext) error {
			return maps.close()
		},
	})

	out.MapOut = bpf.NewMapOut(StatsMaps(maps))
	return
}

type StatsMaps interface {
	MaxEntries() int
	DumpEntries(ctx context.Context, cb func(CtKey, StatsValues) bool) error
}

type statsMaps struct {
	v4StatsMap *StatsMap
	v6StatsMap *StatsMap

	maxStatsEntries int
}

func (s *statsMaps) MaxEntries() int {
	return s.maxStatsEntries
}

func (s *statsMaps) DumpEntries(ctx context.Context, cb func(CtKey, StatsValues) bool) error {
	for _, m := range []*StatsMap{s.v4StatsMap, s.v6StatsMap} {
		if m == nil {
			continue
		}
		if err := m.DumpEntries(ctx, cb); err != nil {
			return err
		}
	}
	return nil
}

func (s *statsMaps) init() error {
	for _, m := range []*StatsMap{s.v4StatsMap, s.v6StatsMap} {
		if m == nil {
			continue
		}
		if err := m.OpenOrCreate(); err != nil {
			return fmt.Errorf("failed to open and create %s map: %w", m.Name(), err)
		}
	}
	return nil
}

func (s *statsMaps) close() error {
	for _, m := range []*StatsMap{s.v4StatsMap, s.v6StatsMap} {
		if m == nil {
			continue
		}
		if err := m.Close(); err != nil {
			return fmt.Errorf("failed to close %s map: %w", m.Name(), err)
		}
	}
	return nil
}
