// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ctmap

import (
	"context"
	"fmt"
	"log/slog"
	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/logging/logfields"
	ciliumebpf "github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// Map names for the CT packet/byte accounting side maps.
const (
	MapNameStats4 = "cilium_ct_stats4"
	MapNameStats6 = "cilium_ct_stats6"
)

// SizeofStatsValue is the size of the per-CPU value stored in the CT stats maps.
const SizeofStatsValue = int(unsafe.Sizeof(StatsValue{}))

// Convenient alias.
type StatsKey CtKey

// StatsRecord represents a single record in the map.
type StatsRecord struct {
	Key   StatsKey
	Value StatsValue
}

// StatsValue must be in sync with struct ct_stats_value in <bpf/lib/conntrack_stats.h>.
type StatsValue struct {
	RxPackets uint64 `align:"rx_packets"`
	RxBytes   uint64 `align:"rx_bytes"`
	TxPackets uint64 `align:"tx_packets"`
	TxBytes   uint64 `align:"tx_bytes"`
}

func (v *StatsValue) New() bpf.MapValue { return &StatsValue{} }

func (v *StatsValue) NewSlice() any { return &StatsValues{} }

func (v *StatsValue) String() string {
	return fmt.Sprintf("RxPackets:%d RxBytes:%d TxPackets:%d TxBytes:%d", v.RxPackets, v.RxBytes, v.TxPackets, v.TxBytes)
}

type StatsValues []StatsValue

func (vs *StatsValues) Aggregate() StatsValue {
	var ret StatsValue
	for _, v := range *vs {
		ret.RxPackets += v.RxPackets
		ret.RxBytes += v.RxBytes
		ret.TxPackets += v.TxPackets
		ret.TxBytes += v.TxBytes
	}
	return ret
}

// StatsMap represents one of the two (v4/v6) CT accounting side maps.
type StatsMap struct {
	*bpf.Map

	mapType statsMapType
}

func newStatsMap(m statsMapType, maxStatsEntries int, log *slog.Logger) (*StatsMap, int) {
	nCPU := possibleCPU(log)
	roundDown := maxStatsEntries % nCPU
	maxStatsEntries -= roundDown

	return &StatsMap{
		Map: bpf.NewMap(
			m.name(),
			m.mapType(),
			m.key(),
			m.value(),
			maxStatsEntries,
			m.flags(),
		),
		mapType: m,
	}, maxStatsEntries
}

// OpenStatsMap opens the existing ct stats (v4 or v6) map.
// Should only be called from cilium-dbg
func OpenStatsMap(logger *slog.Logger, ipv6 bool) (*StatsMap, error) {
	mt := mapTypeStats4
	if ipv6 {
		mt = mapTypeStats6
	}
	m, err := bpf.OpenMap(bpf.MapPath(logger, mt.name()), mt.key(), mt.value())
	if err != nil {
		return nil, err
	}
	return &StatsMap{
		Map:     m,
		mapType: mt,
	}, nil
}

func possibleCPU(logger *slog.Logger) int {
	nCPU, err := ciliumebpf.PossibleCPU()
	if err != nil {
		logger.Error("Failed to determine possible CPUs", logfields.Error, err)
		// Fallback to 1 CPU if we cannot determine the number of CPUs
		return 1
	}
	return nCPU
}

// statsMapType is a type of connection tracking stats map.
type statsMapType int

const (
	mapTypeStats4 statsMapType = iota
	mapTypeStats6
	mapTypeStatsMax
)

func (m statsMapType) String() string {
	switch m {
	case mapTypeStats4:
		return "IPv4 CT stats map"
	case mapTypeStats6:
		return "IPv6 CT stats map"
	}
	return fmt.Sprintf("Unknown (%d)", int(m))
}

func (m statsMapType) mapType() ciliumebpf.MapType {
	return ebpf.LRUCPUHash
}

func (m statsMapType) flags() uint32 {
	return unix.BPF_F_NO_COMMON_LRU
}

func (m statsMapType) name() string {
	switch m {
	case mapTypeStats4:
		return MapNameStats4
	case mapTypeStats6:
		return MapNameStats6
	default:
		panic("Unexpected map type " + m.String())
	}
}

func (m statsMapType) key() bpf.MapKey {
	switch m {
	case mapTypeStats4:
		return &CtKey4Global{}
	case mapTypeStats6:
		return &CtKey6Global{}
	default:
		panic("Unexpected map type " + m.String())
	}
}

func (m statsMapType) value() bpf.MapValue {
	return &StatsValue{}
}

// DumpEntries walks the datapath conntrack stats maps and invokes the callback for each entry.
func (m *StatsMap) DumpEntries(ctx context.Context, cb func(CtKey, StatsValues) bool) error {
	switch m.mapType {
	case mapTypeStats4:
		return iteratePerCPU(ctx, m.Map, func(k *CtKey4Global, v []StatsValue) bool { return cb(k, v) })
	case mapTypeStats6:
		return iteratePerCPU(ctx, m.Map, func(k *CtKey6Global, v []StatsValue) bool { return cb(k, v) })
	default:
		panic("Unexpected map type " + m.mapType.String())
	}
}

// iteratePerCPU is the per-CPU equivalent of iterate: it yields one []VT for every key.
func iteratePerCPU[KT any, VT any, KP bpf.KeyPointer[KT]](ctx context.Context, m *bpf.Map, filterCallback func(key KP, value []VT) bool) error {
	iter := bpf.NewPerCPUBatchIterator[KT, VT, KP](m)
	for k, v := range iter.IterateAll(ctx) {
		if !filterCallback(k, v) {
			break
		}
	}
	return iter.Err()
}
