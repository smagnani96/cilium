// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package conntrack

import (
	"encoding/binary"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"runtime"
	"testing"
	"time"

	"github.com/cilium/ebpf/rlimit"
	"github.com/cilium/fake"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	observerpb "github.com/cilium/cilium/api/v1/observer"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/byteorder"
	resolverTypes "github.com/cilium/cilium/pkg/hubble/resolver/types"
	hubbletestutils "github.com/cilium/cilium/pkg/hubble/testutils"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/tuple"
	"github.com/cilium/cilium/pkg/types"
	"github.com/cilium/cilium/pkg/u8proto"
)

// Size tiers mirror pkg/maps/ctmap's own BenchmarkPrivilegedCtGcTcp{XL,L,M},
// so results are comparable against that benchmark's per-entry costs.
const (
	benchSizeSmall  = 1 << 17
	benchSizeMedium = 1 << 22
	benchSizeLarge  = 1 << 24 // max size
)

// benchAddrPoolSize bounds how many distinct source/destination addresses
// generated entries are drawn from, giving the enrichment resolvers'
// internal caches (see cache.go) a realistic partial hit ratio instead of
// either extreme (a single, always-unique address per entry would never hit
// the cache; a single shared address would always hit it).
const benchAddrPoolSize = 256

var flagsChoices = []uint8{ctmap.TUPLE_F_IN, ctmap.TUPLE_F_OUT, ctmap.TUPLE_F_RELATED}

// BenchmarkPrivilegedGetConntrackEntriesSmall/Medium/Large measure the full
// cost of GetConntrackEntries against a real conntrack map, at the same size
// tiers as BenchmarkPrivilegedCtGcTcpM/L/XL in pkg/maps/ctmap. The map is
// read-only and populated once per size tier, outside the timed loop:
// GetConntrackEntries never mutates it, so there's no per-iteration setup
// cost to pay.
//
// Each size tier fans out into two sub-benchmarks:
//   - enrichment=off: enrich=false is passed to GetConntrackEntries, mirroring
//     a GetConntrackEntriesRequest with Enrich unset.
//   - enrichment=on: enrich=true, exercising endpoint/service/node
//     resolution (see ctEntryToProto) for every entry, backed by the same
//     resolver.Cache-wrapped getters (cache.go) production wiring uses.
//
// Both sub-benchmarks also build the observerpb.GetConntrackEntriesResponse
// wrapper and hand it to a no-op sink, mirroring the response construction
// LocalObserverServer.GetConntrackEntries (pkg/hubble/observer/local_observer.go)
// does around every entry before calling stream.Send.
//
// Run with -benchmem for allocation counts and -cpuprofile to inspect where
// CPU time goes, e.g.:
//
//	PRIVILEGED_TESTS=1 go test -exec "sudo -E" -p=2 ./pkg/hubble/mapexporter/conntrack/ \
//	  -run '^$' -bench BenchmarkPrivilegedGetConntrackEntries -benchmem -benchtime=10x
func BenchmarkPrivilegedGetConntrackEntriesSmall(b *testing.B) {
	benchmarkGetConntrackEntries(b, benchSizeSmall)
}

func BenchmarkPrivilegedGetConntrackEntriesMedium(b *testing.B) {
	benchmarkGetConntrackEntries(b, benchSizeMedium)
}

func BenchmarkPrivilegedGetConntrackEntriesLarge(b *testing.B) {
	benchmarkGetConntrackEntries(b, benchSizeLarge)
}

func benchmarkGetConntrackEntries(b *testing.B, size int) {
	testutils.PrivilegedTest(b)
	logger := hivetest.Logger(b)
	bpf.CheckOrMountFS(logger, "")
	require.NoError(b, rlimit.RemoveMemlock())

	prevSize := option.Config.CTMapEntriesGlobalTCP
	option.Config.CTMapEntriesGlobalTCP = size
	b.Cleanup(func() { option.Config.CTMapEntriesGlobalTCP = prevSize })

	m := ctmap.NewGlobalMap(fmt.Sprintf("%s_bench", ctmap.MapNameTCP4Global), ctmap.MapConfig{TCP: true})
	require.NoError(b, m.OpenOrCreate())
	b.Cleanup(func() { _ = m.Unpin() })

	b.Logf("populating conntrack map (size=%d)", size)
	pool := populateConntrackEntries(b, m, size)

	c := newConntrackExporter(
		Config{EnableConntrack: true, ConntrackRateLimit: 0},
		&benchCTMaps{maps: []*ctmap.Map{m}},
		logger,
		newBenchEndpointGetter(),
		newBenchServiceGetter(pool),
		newBenchNodeGetter(),
	)

	b.Run("enrichment=off", func(b *testing.B) {
		runGetConntrackEntriesBenchmark(b, c, false, size)
	})
	b.Run("enrichment=on", func(b *testing.B) {
		runGetConntrackEntriesBenchmark(b, c, true, size)
	})
}

// runGetConntrackEntriesBenchmark times repeated GetConntrackEntries calls
// against c. size is the number of entries a single dump walks, used only to
// report per-entry metrics alongside the standard per-op ones: ns/op, B/op,
// and allocs/op are per call to GetConntrackEntries, which isn't comparable
// across size tiers - ns/entry, B/entry, and allocs/entry are.
func runGetConntrackEntriesBenchmark(b *testing.B, c *ConntrackExporter, enrich bool, size int) {
	nodeName := "bench-node"
	dumpTime := timestamppb.New(time.Now())

	// testing.B exposes per-op ns/B/allocs only via BenchmarkResult, which
	// the caller of this function never sees; track allocations ourselves,
	// the same way the -benchmem machinery does internally, so per-entry
	// metrics can be derived below.
	var memStatsBefore, memStatsAfter runtime.MemStats
	runtime.ReadMemStats(&memStatsBefore)

	b.ReportAllocs()
	for b.Loop() {
		err := c.GetConntrackEntries(b.Context(), &observerpb.GetConntrackEntriesRequest{Enrich: enrich}, func(e *observerpb.ConntrackEntry) bool {
			// Mirror LocalObserverServer.GetConntrackEntries' response
			// wrapping around every entry, so this measures the same
			// lookup+send shape the real gRPC handler does.
			resp := &observerpb.GetConntrackEntriesResponse{
				ResponseTypes: &observerpb.GetConntrackEntriesResponse_Entry{Entry: e},
				NodeName:      nodeName,
				Time:          dumpTime,
			}
			return benchSendConntrackEntry(resp) == nil
		})
		require.NoError(b, err)
	}

	runtime.ReadMemStats(&memStatsAfter)
	netAllocs := memStatsAfter.Mallocs - memStatsBefore.Mallocs
	netBytes := memStatsAfter.TotalAlloc - memStatsBefore.TotalAlloc

	b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N)/float64(size), "ns/entry")
	b.ReportMetric(float64(netBytes)/float64(b.N)/float64(size), "B/entry")
	b.ReportMetric(float64(netAllocs)/float64(b.N)/float64(size), "allocs/entry")
}

// benchSendConntrackEntry is a no-op stand-in for
// observerpb.Observer_GetConntrackEntriesServer.Send: it exercises building
// and handing off the response message without the cost/complexity of a
// real gRPC stream.
func benchSendConntrackEntry(*observerpb.GetConntrackEntriesResponse) error { return nil }

type benchCTMaps struct {
	maps []*ctmap.Map
}

func (b *benchCTMaps) ActiveMaps() []*ctmap.Map { return b.maps }

// benchServiceID/benchBackendID deterministically derive a service's
// rev_nat_index and a backend's ID from a pool index, letting
// populateConntrackEntries and newBenchServiceGetter agree on the same
// mapping without needing a reverse address lookup.
func benchServiceID(poolIdx int) uint16 { return uint16(poolIdx + 1) }
func benchBackendID(poolIdx int) uint32 { return 1000 + uint32(poolIdx) }

// encodeNatAddrUnion0 is the inverse of natAddrFromUnion0 (conntrack.go): it
// packs addr into the raw [2]uint64 layout a real ct_entry's nat_addr union
// arm is read back from, for IPv4-only generated entries.
func encodeNatAddrUnion0(addr netip.Addr) [2]uint64 {
	var raw [16]byte
	v4 := addr.As4()
	copy(raw[12:16], v4[:])
	return [2]uint64{
		binary.LittleEndian.Uint64(raw[0:8]),
		binary.LittleEndian.Uint64(raw[8:16]),
	}
}

// populateConntrackEntries fills m with size unique, randomly generated TCP
// entries drawn from a pool of benchAddrPoolSize distinct addresses
// (returned so the enrichment getters can resolve them consistently), split
// across the four kinds of entry a real conntrack table mixes - exercising
// every branch ctEntryToProto's enrichment takes:
//   - "plain" (majority): never serviced; RevNAT/NatPort/Union0 all zero.
//   - "service": a TUPLE_F_SERVICE entry; RevNAT and Union0[1] (backend_id)
//     are set.
//   - "regular-serviced": a normal CT_INGRESS/CT_EGRESS entry for a serviced
//     connection; RevNAT is set, Union0/NatPort stay zero, the non-DSR case.
//   - "dsr": RevNAT is zero but NatPort and Union0 (nat_addr) are set, the only
//     case where service resolution falls back to GetServiceByAddr.
func populateConntrackEntries(tb testing.TB, m ctmap.CtMap, size int) []netip.Addr {
	tb.Helper()

	pool := make([]netip.Addr, benchAddrPoolSize)
	for i := range pool {
		pool[i] = netip.MustParseAddr(fake.IP(fake.WithIPv4()))
	}

	genEntry := func() (ctmap.CtKey4Global, *ctmap.CtEntry) {
		srcIdx, dstIdx := rand.IntN(len(pool)), rand.IntN(len(pool))
		src, dst := pool[srcIdx], pool[dstIdx]

		entry := &ctmap.CtEntry{
			Packets:          8,
			Bytes:            432,
			Lifetime:         37459,
			Flags:            ctmap.SeenNonSyn | ctmap.RxClosing,
			TxFlagsSeen:      0x02,
			RxFlagsSeen:      0x14,
			SourceSecurityID: 50_000 + uint32(dstIdx),
			LastTxReport:     15856,
			LastRxReport:     15856,
		}

		var keyFlags uint8
		switch n := rand.IntN(100); {
		case n < 10: // service entry
			keyFlags = ctmap.TUPLE_F_SERVICE
			entry.RevNAT = byteorder.HostToNetwork16(benchServiceID(dstIdx))
			entry.Union0[1] = uint64(benchBackendID(dstIdx))
		case n < 40: // regular entry, serviced (common non-DSR path)
			keyFlags = flagsChoices[rand.IntN(len(flagsChoices))]
			entry.RevNAT = byteorder.HostToNetwork16(benchServiceID(dstIdx))
		case n < 50: // regular entry, DSR
			keyFlags = flagsChoices[rand.IntN(len(flagsChoices))]
			entry.NatPort = byteorder.HostToNetwork16(80)
			entry.Union0 = encodeNatAddrUnion0(dst)
		default: // plain, never serviced
			keyFlags = flagsChoices[rand.IntN(len(flagsChoices))]
		}

		key := ctmap.CtKey4Global{
			TupleKey4Global: tuple.TupleKey4Global{
				TupleKey4: tuple.TupleKey4{
					SourceAddr: types.IPv4(src.As4()),
					DestAddr:   types.IPv4(dst.As4()),
					SourcePort: byteorder.HostToNetwork16(uint16(fake.Port())),
					DestPort:   byteorder.HostToNetwork16(80),
					NextHeader: u8proto.TCP,
					Flags:      keyFlags,
				},
			},
		}
		return key, entry
	}

	seen := make(map[ctmap.CtKey4Global]struct{}, size)
	for len(seen) < size {
		key, entry := genEntry()
		if _, exists := seen[key]; exists {
			continue
		}
		if err := m.Update(&key, entry); err != nil {
			tb.Fatal(err)
		}
		seen[key] = struct{}{}
	}
	return pool
}

// newBenchEndpointGetter returns a resolverTypes.EndpointGetter that
// resolves any address to a synthetic pod endpoint, except for addresses
// ending in .0, which resolve to the remote-node identity instead - giving
// mayBeNodeAddress (conntrack.go) a minority of addresses to route through
// NodeGetter, like real remote-node traffic would.
func newBenchEndpointGetter() resolverTypes.EndpointGetter {
	return &hubbletestutils.FakeEndpointGetter{
		OnResolveEndpoint: func(ip netip.Addr, securityID uint32, _ resolverTypes.DatapathContext) *flowpb.Endpoint {
			if ip.As4()[3] == 0 {
				return &flowpb.Endpoint{Identity: uint32(identity.ReservedIdentityRemoteNode)}
			}
			return &flowpb.Endpoint{
				PodName:   "pod-" + ip.String(),
				Namespace: "bench",
				Identity:  50_000 + securityID,
			}
		},
	}
}

// newBenchServiceGetter returns a resolverTypes.ServiceGetter backed by
// pool: GetBackendAddrByID resolves exactly the backend IDs
// populateConntrackEntries assigned to pool addresses (see benchBackendID),
// and everything else resolves unconditionally, giving every enrichment
// path a realistic "found" result to build on.
func newBenchServiceGetter(pool []netip.Addr) resolverTypes.ServiceGetter {
	backendAddrByID := make(map[uint32]netip.Addr, len(pool))
	for idx, addr := range pool {
		backendAddrByID[benchBackendID(idx)] = addr
	}
	return &hubbletestutils.FakeServiceGetter{
		OnGetServiceByAddr: func(ip netip.Addr, _ uint16) *flowpb.Service {
			return &flowpb.Service{Namespace: "bench", Name: "svc-" + ip.String()}
		},
		OnGetServiceByRevNatIndex: func(revNatIndex uint32) *flowpb.Service {
			return &flowpb.Service{Namespace: "bench", Name: fmt.Sprintf("svc-%d", revNatIndex)}
		},
		OnGetBackendAddrByID: func(backendID uint32, _ bool) (netip.Addr, bool) {
			addr, ok := backendAddrByID[backendID]
			return addr, ok
		},
	}
}

// newBenchNodeGetter returns a resolverTypes.NodeGetter that resolves any
// address to a synthetic node name.
func newBenchNodeGetter() resolverTypes.NodeGetter {
	return &hubbletestutils.FakeNodeGetter{
		OnGetNodeNameByIP: func(ip netip.Addr) string {
			return "bench-node-" + ip.String()
		},
	}
}
