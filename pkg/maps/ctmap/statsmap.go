// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ctmap

import (
	"fmt"
	"strings"
	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/linux/probes"
	"github.com/cilium/cilium/pkg/ebpf"
	ciliumebpf "github.com/cilium/ebpf"
)

const (
	MapNameStats4 = "cilium_ct_stats4"
	MapNameStats6 = "cilium_ct_stats6"
)

const SizeofStatsValue = int(unsafe.Sizeof(CtStats{}))

type StatsKey CtKey

type StatsRecord struct {
	Key   StatsKey
	Value *CtStats
}

func (s StatsRecord) Dump(sb *strings.Builder) error {
	if !s.Key.ToHost().Dump(sb, true) {
		return fmt.Errorf("unable to dump key: %s", sb.String())
	}
	fmt.Fprintf(sb, " %s", s.Value.String())
	return nil
}

// CtStats must be in sync with struct ct_stats in <bpf/lib/conntrack_stats.h>.
type CtStats struct {
	RxPackets uint64 `align:"rx_packets"`
	RxBytes   uint64 `align:"rx_bytes"`
	TxPackets uint64 `align:"tx_packets"`
	TxBytes   uint64 `align:"tx_bytes"`
}

func (v *CtStats) New() bpf.MapValue { return &CtStats{} }

func (v *CtStats) String() string {
	return fmt.Sprintf("RxPackets:%d RxBytes:%d TxPackets:%d TxBytes:%d", v.RxPackets, v.RxBytes, v.TxPackets, v.TxBytes)
}

type StatsMap interface {
	Open() error
	Close() error
	Path() (string, error)
	Name() string
	Family() string
	DeleteAll() error
	Lookup(key StatsKey) (*CtStats, error)
	LookupAndDelete(key StatsKey) (*CtStats, bool, error)
	DumpWithCallback(callback func(key StatsKey, value *CtStats)) error
}

type statsMap struct {
	*bpf.Map

	mapType statsMapType
}

func (m *statsMap) DeleteAll() error {
	return m.Map.DeleteAll()
}

func (m *statsMap) DumpWithCallback(cb func(key StatsKey, value *CtStats)) error {
	switch m.mapType {
	case mapTypeStats4:
		return iterate[CtKey4Global, CtStats](m.Map, func(key bpf.MapKey, value bpf.MapValue) {
			cb(key.(CtKey), value.(*CtStats))
		})
	case mapTypeStats6:
		return iterate[CtKey6Global, CtStats](m.Map, func(key bpf.MapKey, value bpf.MapValue) {
			cb(key.(CtKey), value.(*CtStats))
		})
	default:
		panic("Unexpected map type " + m.mapType.String())
	}
}

// LookupAndDelete retrieves and removes the stats entry for key.
// ok is false (with a nil error) if no entry existed (e.g. the key was LRU evicted).
// Use underlying LookupAndDelete if available, otherwise fall back to separate
// Lookup and Delete operations.
func (m *statsMap) LookupAndDelete(key StatsKey) (value *CtStats, ok bool, err error) {
	if probes.HaveLRUHashLookupAndDelete() == nil {
		deleted, v, err := m.Map.LookupAndDelete(key)
		if err != nil || !deleted {
			return nil, false, err
		}
		return v.(*CtStats), true, nil
	}

	v, err := m.Map.Lookup(key)
	if err != nil {
		return nil, false, err
	}
	err = m.Map.Delete(key)
	if err != nil {
		return nil, false, err
	}
	return v.(*CtStats), true, nil
}

func (m *statsMap) Lookup(key StatsKey) (value *CtStats, err error) {
	v, err := m.Map.Lookup(key)
	if err != nil || v == nil {
		return nil, err
	}
	return v.(*CtStats), nil
}

func newStatsMap(m statsMapType, maxStatsEntries int) *statsMap {
	return &statsMap{
		Map: bpf.NewMap(
			m.name(),
			m.mapType(),
			m.key(),
			m.value(),
			maxStatsEntries,
			m.flags(),
		),
		mapType: m,
	}
}

func (m *statsMap) Name() string {
	return m.mapType.name()
}

func (m *statsMap) Family() string {
	return m.mapType.family()
}

func GlobalStatsMaps(ipv4, ipv6 bool) (ipv4Map, ipv6Map StatsMap) {
	if ipv4 {
		ipv4Map = newStatsMap(mapTypeStats4, 0)
	}
	if ipv6 {
		ipv6Map = newStatsMap(mapTypeStats6, 0)
	}
	return
}

// OpenCTStatsMap is a convenience function to open CT stats maps. It is the
// responsibility of the caller to ensure that m.Close() is called after this
// function.
func OpenCTStatsMap(m StatsMap) (path string, err error) {
	path, err = m.Path()
	if err == nil {
		err = m.Open()
	}
	return
}

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
	return ebpf.LRUHash
}

func (m statsMapType) family() string {
	switch m {
	case mapTypeStats4:
		return "ipv4"
	case mapTypeStats6:
		return "ipv6"
	default:
		return "unknown"
	}
}

func (m statsMapType) flags() uint32 {
	return 0
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
	return &CtStats{}
}

// PruneStatsEntry deletes the stats entry matching a pruned CT entry
// (identified by event.Key) so that the accounting side maps never outlive
// the CT entries they describe.
func PruneStatsEntry(statsMap StatsMap, event GCEvent) {
	if statsMap == nil {
		return
	}

	statsMap.LookupAndDelete(event.Key)
}
