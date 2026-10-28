// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ctmap

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/ctstats"
	"github.com/cilium/cilium/pkg/datapath/linux/probes"
	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/u8proto"

	ciliumebpf "github.com/cilium/ebpf"
	"github.com/prometheus/client_golang/prometheus"
)

// Fails to compile if the ctstats flags diverge from the TUPLE_F_* ones.
var (
	_ = [1]struct{}{}[ctstats.TupleFlagIn-TUPLE_F_IN]
	_ = [1]struct{}{}[ctstats.TupleFlagService-TUPLE_F_SERVICE]
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

func (v *CtStats) Add(other *CtStats) {
	v.RxPackets += other.RxPackets
	v.RxBytes += other.RxBytes
	v.TxPackets += other.TxPackets
	v.TxBytes += other.TxBytes
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
	DumpWithCallback(callback func(key StatsKey, value *CtStats) bool) error
}

type statsMap struct {
	*bpf.Map

	mapType statsMapType
}

func (m *statsMap) DeleteAll() error {
	return m.Map.DeleteAll()
}

func (m *statsMap) DumpWithCallback(cb func(key StatsKey, value *CtStats) bool) error {
	switch m.mapType {
	case mapTypeStats4:
		return iterate[CtKey4Global, CtStats](m.Map, func(key bpf.MapKey, value bpf.MapValue) bool {
			return cb(key.(CtKey), value.(*CtStats))
		})
	case mapTypeStats6:
		return iterate[CtKey6Global, CtStats](m.Map, func(key bpf.MapKey, value bpf.MapValue) bool {
			return cb(key.(CtKey), value.(*CtStats))
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
func PruneStatsEntry(statsMap StatsMap, event GCEvent, cache *ctstats.Cache) {
	if statsMap == nil {
		return
	}

	value, ok, err := statsMap.LookupAndDelete(event.Key)
	if err != nil || !ok {
		return
	}

	if t, ok := ctKeyToTuple(event.Key); ok {
		cache.RecordPruned(t, ctStatsToValue(value))
	}

	if event.Key.GetFlags()&TUPLE_F_SERVICE != 0 {
		return
	}

	family := statsMap.Family()
	var protocol string
	if isKeyTCP(event.Key) {
		protocol = gcProtocolTCP.String()
	} else {
		protocol = gcProtocolAny.String()
	}

	metrics.ConntrackStatsGCBytes.WithLabelValues(family, protocol, metricsDeleted, metricsIngress).Add(float64(value.RxBytes))
	metrics.ConntrackStatsGCBytes.WithLabelValues(family, protocol, metricsDeleted, metricsEgress).Add(float64(value.TxBytes))
	metrics.ConntrackStatsGCPackets.WithLabelValues(family, protocol, metricsDeleted, metricsIngress).Add(float64(value.RxPackets))
	metrics.ConntrackStatsGCPackets.WithLabelValues(family, protocol, metricsDeleted, metricsEgress).Add(float64(value.TxPackets))
}

// ctKeyToTuple converts a stats map key into the canonical client -> server
// tuple. The datapath stores keys reversed, but differently per flag:
//   - IN/OUT: addresses are swapped, ports are not.
//   - SERVICE: addresses are not swapped, ports are.
func ctKeyToTuple(key CtKey) (ctstats.Tuple, bool) {
	var src, dst netip.Addr
	var srcPort, dstPort uint16
	var proto, flags uint8

	switch k := key.ToHost().(type) {
	case *CtKey4Global:
		src, dst = k.SourceAddr.Addr(), k.DestAddr.Addr()
		srcPort, dstPort = k.SourcePort, k.DestPort
		proto, flags = uint8(k.NextHeader), k.Flags
	case *CtKey6Global:
		src, dst = k.SourceAddr.Addr(), k.DestAddr.Addr()
		srcPort, dstPort = k.SourcePort, k.DestPort
		proto, flags = uint8(k.NextHeader), k.Flags
	default:
		return ctstats.Tuple{}, false
	}

	if flags&TUPLE_F_SERVICE != 0 {
		srcPort, dstPort = dstPort, srcPort
	} else {
		src, dst = dst, src
	}

	return ctstats.Tuple{Src: src, Dst: dst, SrcPort: srcPort, DstPort: dstPort, Proto: proto, Flags: flags}, true
}

func ctStatsToValue(stats *CtStats) ctstats.Value {
	return ctstats.Value{
		RxBytes:   stats.RxBytes,
		TxBytes:   stats.TxBytes,
		RxPackets: stats.RxPackets,
		TxPackets: stats.TxPackets,
	}
}

func newStatsSource(maps StatsMaps) ctstats.Source {
	return func(ctx context.Context, yield func(ctstats.Tuple, ctstats.Value) bool) error {
		for _, ipv6 := range []bool{false, true} {
			m := maps.StatsMapForFamily(ipv6)
			if m == nil {
				continue
			}
			var stop bool
			err := m.DumpWithCallback(func(key StatsKey, value *CtStats) bool {
				if t, ok := ctKeyToTuple(key); ok {
					stop = !yield(t, ctStatsToValue(value))
				}
				return !stop
			})
			if err != nil {
				return fmt.Errorf("failed to dump %s: %w", m.Name(), err)
			}
			if stop {
				return nil
			}
		}
		return nil
	}
}

// statsCollector is a prometheus.Collector exposing the alive packet/byte/entry
// counts from the ctstats cache, so the stats maps are only scanned (at most once
// per cache TTL) when the metrics endpoint is queried.
type statsCollector struct {
	logger *slog.Logger
	cache  *ctstats.Cache

	bytesDesc   *prometheus.Desc
	packetsDesc *prometheus.Desc
	entriesDesc *prometheus.Desc
}

func newStatsCollector(logger *slog.Logger, cache *ctstats.Cache) *statsCollector {
	return &statsCollector{
		logger: logger,
		cache:  cache,
		bytesDesc: prometheus.NewDesc(
			prometheus.BuildFQName(metrics.Namespace, metrics.SubsystemDatapath, "conntrack_stats_bytes"),
			"Current number of bytes accounted for by alive connection tracking entries "+
				"labeled by datapath family, protocol, status, and direction",
			[]string{metrics.LabelDatapathFamily, metrics.LabelProtocol, metrics.LabelStatus, metrics.LabelDirection}, nil,
		),
		packetsDesc: prometheus.NewDesc(
			prometheus.BuildFQName(metrics.Namespace, metrics.SubsystemDatapath, "conntrack_stats_packets"),
			"Current number of packets accounted for by alive connection tracking entries "+
				"labeled by datapath family, protocol, status, and direction",
			[]string{metrics.LabelDatapathFamily, metrics.LabelProtocol, metrics.LabelStatus, metrics.LabelDirection}, nil,
		),
		entriesDesc: prometheus.NewDesc(
			prometheus.BuildFQName(metrics.Namespace, metrics.SubsystemDatapath, "conntrack_stats_entries"),
			"Current number of connection tracking alive entries "+
				"labeled by datapath family, status, and protocol",
			[]string{metrics.LabelDatapathFamily, metrics.LabelStatus, metrics.LabelProtocol}, nil,
		),
	}
}

func (c *statsCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.bytesDesc
	ch <- c.packetsDesc
	ch <- c.entriesDesc
}

func (c *statsCollector) Collect(ch chan<- prometheus.Metric) {
	snapshot, err := c.cache.Snapshot(context.Background())
	if err != nil {
		c.logger.Warn("Failed to refresh CT stats", logfields.Error, err)
	}
	if snapshot == nil {
		return
	}

	type group struct {
		family, protocol string
	}
	type total struct {
		ctstats.Value
		entries uint
	}
	totals := make(map[group]*total)
	for _, family := range []string{mapTypeStats4.family(), mapTypeStats6.family()} {
		for _, protocol := range []gcProtocol{gcProtocolTCP, gcProtocolAny} {
			totals[group{family, protocol.String()}] = &total{}
		}
	}

	for t, e := range snapshot.Deduplicated() {
		// A service entry accounts again the packets of its backend entry.
		if !e.Alive || t.Flags&ctstats.TupleFlagService != 0 {
			continue
		}
		family := mapTypeStats4.family()
		if t.Src.Is6() {
			family = mapTypeStats6.family()
		}
		protocol := gcProtocolAny
		if u8proto.U8proto(t.Proto) == u8proto.TCP {
			protocol = gcProtocolTCP
		}
		tot := totals[group{family, protocol.String()}]
		tot.Add(e.Value)
		tot.entries++
	}

	for g, t := range totals {
		ch <- prometheus.MustNewConstMetric(c.bytesDesc, prometheus.GaugeValue, float64(t.RxBytes), g.family, g.protocol, metricsAlive, metricsIngress)
		ch <- prometheus.MustNewConstMetric(c.bytesDesc, prometheus.GaugeValue, float64(t.TxBytes), g.family, g.protocol, metricsAlive, metricsEgress)
		ch <- prometheus.MustNewConstMetric(c.packetsDesc, prometheus.GaugeValue, float64(t.RxPackets), g.family, g.protocol, metricsAlive, metricsIngress)
		ch <- prometheus.MustNewConstMetric(c.packetsDesc, prometheus.GaugeValue, float64(t.TxPackets), g.family, g.protocol, metricsAlive, metricsEgress)
		ch <- prometheus.MustNewConstMetric(c.entriesDesc, prometheus.GaugeValue, float64(t.entries), g.family, metricsAlive, g.protocol)
	}
}

func registerStatsCollector(logger *slog.Logger, daemonCfg *option.DaemonConfig, registry *metrics.Registry, cache *ctstats.Cache) {
	if !daemonCfg.BPFConntrackStats || cache == nil {
		return
	}
	if err := registry.Register(newStatsCollector(logger, cache)); err != nil {
		logger.Error("Failed to register CT stats collector to Prometheus registry. "+
			"cilium_datapath_conntrack_stats metrics will not be collected",
			logfields.Error, err,
		)
	}
}
