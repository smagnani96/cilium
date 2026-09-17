// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package conntrack

import (
	"encoding/binary"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	observerpb "github.com/cilium/cilium/api/v1/observer"
	"github.com/cilium/cilium/pkg/byteorder"
	resolverTypes "github.com/cilium/cilium/pkg/hubble/resolver/types"
	"github.com/cilium/cilium/pkg/hubble/testutils"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/tuple"
	"github.com/cilium/cilium/pkg/types"
	"github.com/cilium/cilium/pkg/u8proto"
	"github.com/cilium/hive/hivetest"
)

type mockCTMaps struct {
	calls atomic.Int32
}

func (m *mockCTMaps) ActiveMaps() []*ctmap.Map {
	m.calls.Add(1)
	return nil
}

func TestConntrackExporter_Disabled(t *testing.T) {
	c := newConntrackExporter(Config{EnableCTSnapshot: false}, &mockCTMaps{}, hivetest.Logger(t), nil, nil)
	snap, err := c.GetConntrackSnapshot(t.Context())
	require.ErrorIs(t, err, ErrExporterDisabled)
	require.Nil(t, snap)
}

func TestConntrackExporter_Cache(t *testing.T) {
	ctMaps := &mockCTMaps{}
	c := newConntrackExporter(Config{EnableCTSnapshot: true, ConntrackCacheTTL: 10 * time.Second}, ctMaps, hivetest.Logger(t), nil, nil)

	snap1, err := c.GetConntrackSnapshot(t.Context())
	require.NoError(t, err)
	require.NotNil(t, snap1)

	snap2, err := c.GetConntrackSnapshot(t.Context())
	require.NoError(t, err)
	require.Same(t, snap1, snap2, "second call within the TTL should reuse the cached snapshot")
	require.EqualValues(t, 1, ctMaps.calls.Load())

	c.cfg.ConntrackCacheTTL = 0

	snap3, err := c.GetConntrackSnapshot(t.Context())
	require.NoError(t, err)
	require.NotSame(t, snap1, snap3, "call after the TTL has expired should trigger a refresh")
	require.EqualValues(t, 2, ctMaps.calls.Load())
}

func TestAggregateCtEntry(t *testing.T) {
	entries := make(map[ctAggregationKey]*observerpb.ConntrackEntry)

	// Pod names are looked up by the (post-swap) source/destination IP of
	// each aggregated flow, so every distinct flow below needs a distinct
	// address to resolve to a distinct, assertable pod name.
	podNames := map[string]string{
		"10.0.0.2": "pod-src-v4",
		"10.0.0.1": "pod-dst-v4",
		"fd00::1":  "pod-src-v6",
		"fd00::2":  "pod-dst-v6-b",
		"fd01::2":  "pod-dst-v6-c",
		"10.0.0.3": "pod-src-revnat",
		"10.0.0.4": "pod-dst-revnat",
		"10.0.0.5": "pod-backend",
		"10.0.0.7": "pod-src-natport",
		"10.0.0.6": "pod-dst-natport",
	}
	epGetter := &testutils.FakeEndpointGetter{
		OnResolveEndpoint: func(ip netip.Addr, _ uint32, _ resolverTypes.DatapathContext) *flowpb.Endpoint {
			podName, ok := podNames[ip.String()]
			if !ok {
				return nil
			}
			return &flowpb.Endpoint{PodName: podName}
		},
	}

	const (
		revNatIndex   = 7
		backendID     = 42
		backendAddr   = "10.0.0.5"
		natPort       = 5353
		natAddrString = "10.0.0.8"
	)
	svcGetter := &testutils.FakeServiceGetter{
		OnGetServiceByAddr: func(ip netip.Addr, port uint16) *flowpb.Service {
			if ip.String() == natAddrString && port == natPort {
				return &flowpb.Service{Name: "svc-natport"}
			}
			return nil
		},
		OnGetServiceByRevNatIndex: func(revNatIdx uint32) *flowpb.Service {
			if revNatIdx == revNatIndex {
				return &flowpb.Service{Name: "svc-revnat"}
			}
			return nil
		},
	}

	for _, s := range []struct {
		record      ctmap.CtMapRecord
		assertEntry *observerpb.ConntrackEntry
	}{
		{
			// TUPLE_F_SERVICE entries store addresses in natural order and
			// swap the ports: SourceAddr:DestPort is the real client
			// (10.0.0.2:1234), DestAddr:SourcePort is the service frontend
			// (10.0.0.1:80).
			// Service entry resolved via rev_nat_index, with its backend
			// resolved via backend_id (Union0[1]).
			record: ctmap.CtMapRecord{
				Key: &ctmap.CtKey4Global{
					TupleKey4Global: tuple.TupleKey4Global{
						TupleKey4: tuple.TupleKey4{
							SourceAddr: types.IPv4{10, 0, 0, 2},
							DestAddr:   types.IPv4{10, 0, 0, 1},
							SourcePort: byteorder.HostToNetwork16(80),
							DestPort:   byteorder.HostToNetwork16(1234),
							NextHeader: u8proto.TCP,
							Flags:      ctmap.TUPLE_F_SERVICE,
						},
					},
				},
				Value: ctmap.CtEntry{
					Packets: 10,
					Bytes:   2000,
					RevNAT:  byteorder.HostToNetwork16(revNatIndex),
					Union0:  [2]uint64{0, backendID},
				},
			},
			assertEntry: &observerpb.ConntrackEntry{
				SourceIp:        "10.0.0.2",
				DestinationIp:   "10.0.0.1",
				DestinationPort: 80,
				Protocol:        uint32(u8proto.TCP),
				Packets:         10,
				Bytes:           2000,
				Count:           1,
				Source:          &flowpb.Endpoint{PodName: "pod-src-v4"},
				Destination:     &flowpb.Endpoint{PodName: "pod-dst-v4"},
				Service:         &flowpb.Service{Name: "svc-revnat"},
			},
		},
		{
			// Same 4-tuple as above except for the client's port (DestPort
			// for a SERVICE entry), which is excluded from the aggregation
			// key: this must merge into the same entry rather than create a
			// new one.
			record: ctmap.CtMapRecord{
				Key: &ctmap.CtKey4Global{
					TupleKey4Global: tuple.TupleKey4Global{
						TupleKey4: tuple.TupleKey4{
							SourceAddr: types.IPv4{10, 0, 0, 2},
							DestAddr:   types.IPv4{10, 0, 0, 1},
							SourcePort: byteorder.HostToNetwork16(80),
							DestPort:   byteorder.HostToNetwork16(1235),
							NextHeader: u8proto.TCP,
							Flags:      ctmap.TUPLE_F_SERVICE,
						},
					},
				},
				Value: ctmap.CtEntry{
					Packets: 100,
					Bytes:   5000,
				},
			},
			assertEntry: &observerpb.ConntrackEntry{
				SourceIp:        "10.0.0.2",
				DestinationIp:   "10.0.0.1",
				DestinationPort: 80,
				Protocol:        uint32(u8proto.TCP),
				Packets:         110,
				Bytes:           7000,
				Count:           2,
				Source:          &flowpb.Endpoint{PodName: "pod-src-v4"},
				Destination:     &flowpb.Endpoint{PodName: "pod-dst-v4"},
				Service:         &flowpb.Service{Name: "svc-revnat"},
			},
		},
		{
			// Service entry resolved via the NAT'd address/port
			// (Union0/nat_port), independently of rev_nat_index.
			record: ctmap.CtMapRecord{
				Key: &ctmap.CtKey4Global{
					TupleKey4Global: tuple.TupleKey4Global{
						TupleKey4: tuple.TupleKey4{
							SourceAddr: types.IPv4{10, 0, 0, 6},
							DestAddr:   types.IPv4{10, 0, 0, 7},
							SourcePort: byteorder.HostToNetwork16(3333),
							DestPort:   byteorder.HostToNetwork16(53),
							NextHeader: u8proto.UDP,
						},
					},
				},
				Value: ctmap.CtEntry{
					Packets: 2,
					Bytes:   200,
					NatPort: byteorder.HostToNetwork16(natPort),
					Union0:  ipv4NatUnion0(10, 0, 0, 8),
				},
			},
			assertEntry: &observerpb.ConntrackEntry{
				SourceIp:        "10.0.0.7",
				DestinationIp:   "10.0.0.6",
				DestinationPort: 53,
				Protocol:        uint32(u8proto.UDP),
				Packets:         2,
				Bytes:           200,
				Count:           1,
				Source:          &flowpb.Endpoint{PodName: "pod-src-natport"},
				Destination:     &flowpb.Endpoint{PodName: "pod-dst-natport"},
				Service:         &flowpb.Service{Name: "svc-natport"},
			},
		},
		{
			// Different destination port/protocol family: a new entry.
			record: ctmap.CtMapRecord{
				Key: &ctmap.CtKey6Global{
					TupleKey6Global: tuple.TupleKey6Global{
						TupleKey6: tuple.TupleKey6{
							SourceAddr: types.IPv6{0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
							DestAddr:   types.IPv6{0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
							SourcePort: byteorder.HostToNetwork16(1234),
							DestPort:   byteorder.HostToNetwork16(8472),
							NextHeader: u8proto.UDP,
							Flags:      ctmap.TUPLE_F_IN,
						},
					},
				},
				Value: ctmap.CtEntry{
					Packets: 1,
					Bytes:   80,
				},
			},
			// Address inverted as TUPLE_F_IN
			assertEntry: &observerpb.ConntrackEntry{
				SourceIp:        "fd00::1",
				DestinationIp:   "fd00::2",
				DestinationPort: 8472,
				Protocol:        uint32(u8proto.UDP),
				Packets:         1,
				Bytes:           80,
				Count:           1,
				Source:          &flowpb.Endpoint{PodName: "pod-src-v6"},
				Destination:     &flowpb.Endpoint{PodName: "pod-dst-v6-b"},
			},
		},
		{
			// Different source address: another new entry.
			record: ctmap.CtMapRecord{
				Key: &ctmap.CtKey6Global{
					TupleKey6Global: tuple.TupleKey6Global{
						TupleKey6: tuple.TupleKey6{
							SourceAddr: types.IPv6{0xfd, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
							DestAddr:   types.IPv6{0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
							SourcePort: byteorder.HostToNetwork16(1234),
							DestPort:   byteorder.HostToNetwork16(8472),
							NextHeader: u8proto.UDP,
							Flags:      ctmap.TUPLE_F_OUT,
						},
					},
				},
				Value: ctmap.CtEntry{
					Packets: 6,
					Bytes:   400,
				},
			},
			// Address inverted as TUPLE_F_OUT
			assertEntry: &observerpb.ConntrackEntry{
				SourceIp:        "fd00::1",
				DestinationIp:   "fd01::2",
				DestinationPort: 8472,
				Protocol:        uint32(u8proto.UDP),
				Packets:         6,
				Bytes:           400,
				Count:           1,
				Source:          &flowpb.Endpoint{PodName: "pod-src-v6"},
				Destination:     &flowpb.Endpoint{PodName: "pod-dst-v6-c"},
			},
		},
	} {
		key, ok := aggregateCtKey(s.record.Key)
		require.True(t, ok, "failed to aggregate key")

		aggregateCtEntry(entries, s.record.Key, &s.record.Value, epGetter, svcGetter)
		e, ok := entries[key]
		require.True(t, ok, "expected aggregation key not found")
		require.Equal(t, s.assertEntry.String(), e.String())
	}
}

// ipv4NatUnion0 encodes an IPv4 address the same way the datapath packs it
// into ctmap.CtEntry.Union0, inverting natAddrFromUnion0.
func ipv4NatUnion0(a, b, c, d byte) [2]uint64 {
	var raw [16]byte
	copy(raw[12:16], []byte{a, b, c, d})
	return [2]uint64{
		binary.LittleEndian.Uint64(raw[0:8]),
		binary.LittleEndian.Uint64(raw[8:16]),
	}
}
