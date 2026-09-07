// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package conntrack

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	observerpb "github.com/cilium/cilium/api/v1/observer"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/hubble/mapexporter/common"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/tuple"
	"github.com/cilium/cilium/pkg/types"
	"github.com/cilium/cilium/pkg/u8proto"
	"github.com/cilium/hive/hivetest"
)

var (
	txReportDiff = int64(-10)
	lifetimeDiff = int64(+50)
	clock        = common.BPFClock{Now: time.Unix(1700000000, 0), NowCTSec: 1000, Converter: func(t uint64) uint64 { return t }}
	key4         = &ctmap.CtKey4Global{
		TupleKey4Global: tuple.TupleKey4Global{
			TupleKey4: tuple.TupleKey4{
				SourceAddr: types.IPv4{10, 0, 0, 2},
				DestAddr:   types.IPv4{10, 0, 0, 1},
				SourcePort: byteorder.HostToNetwork16(1234),
				DestPort:   byteorder.HostToNetwork16(80),
				NextHeader: u8proto.TCP,
				Flags:      ctmap.TUPLE_F_SERVICE,
			},
		},
	}
	key6 = &ctmap.CtKey6Global{
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
	}
	entry = &ctmap.CtEntry{
		Packets:      10,
		Bytes:        2000,
		Lifetime:     uint32(clock.NowCTSec + lifetimeDiff),
		Flags:        ctmap.NodePort,
		TxFlagsSeen:  0x1,
		RxFlagsSeen:  0x2,
		LastTxReport: uint32(clock.NowCTSec + txReportDiff),
		LastRxReport: uint32(clock.NowCTSec),
	}
)

type mockCTMaps struct {
}

func (m *mockCTMaps) ActiveMaps() []*ctmap.Map {
	return nil
}

func TestConntrackExporter_API(t *testing.T) {
	c := newConntrackExporter(Config{EnableConntrack: true, ConntrackRateLimit: 30 * time.Second}, &mockCTMaps{}, hivetest.Logger(t))
	err := c.GetConntrackEntries(t.Context(), &observerpb.GetConntrackEntriesRequest{}, nil)
	require.Nil(t, err)

	err = c.GetConntrackEntries(t.Context(), &observerpb.GetConntrackEntriesRequest{}, nil)
	require.ErrorIs(t, err, common.ErrExportRateLimitExceeded)

	c = newConntrackExporter(Config{EnableConntrack: true, ConntrackRateLimit: 30 * time.Second}, &mockCTMaps{}, hivetest.Logger(t))
	c.inFlight.Store(true)
	err = c.GetConntrackEntries(t.Context(), &observerpb.GetConntrackEntriesRequest{}, nil)
	require.ErrorIs(t, err, common.ErrExportInProgress)

	c = newConntrackExporter(Config{EnableConntrack: false, ConntrackRateLimit: 30 * time.Second}, &mockCTMaps{}, hivetest.Logger(t))
	err = c.GetConntrackEntries(t.Context(), &observerpb.GetConntrackEntriesRequest{}, nil)
	require.ErrorIs(t, err, common.ErrExporterDisabled)
}

func TestConntrackExporter_Conversion(t *testing.T) {
	for _, s := range []struct {
		key  ctmap.CtKey
		ipv6 bool
	}{
		{key: key4, ipv6: false},
		{key: key6, ipv6: true},
	} {
		var (
			isTCP        bool
			isDirIn      bool
			saddr, daddr string
			sport, dport uint16
			proto        u8proto.U8proto
		)

		if s.ipv6 {
			key := s.key.(*ctmap.CtKey6Global)
			saddr = key.DestAddr.String()
			daddr = key.SourceAddr.String()
			sport = key.SourcePort
			dport = key.DestPort
			proto = key.NextHeader
			isDirIn = key.Flags&ctmap.TUPLE_F_IN != 0
			isTCP = key.NextHeader == u8proto.TCP
		} else {
			key := s.key.(*ctmap.CtKey4Global)
			saddr = key.DestAddr.String()
			daddr = key.SourceAddr.String()
			sport = key.SourcePort
			dport = key.DestPort
			proto = key.NextHeader
			isDirIn = key.Flags&ctmap.TUPLE_F_IN != 0
			isTCP = key.NextHeader == u8proto.TCP
		}

		got := ctEntryToProto(s.key, entry, clock)
		require.NotNil(t, got)

		assert.Equal(t, saddr, got.SourceIp)
		assert.Equal(t, daddr, got.DestinationIp)
		assert.Equal(t, uint32(byteorder.HostToNetwork16(sport)), got.SourcePort)
		assert.Equal(t, uint32(byteorder.HostToNetwork16(dport)), got.DestinationPort)
		assert.Equal(t, uint32(proto), got.Protocol)

		assert.True(t, got.Flags.NodePort)
		assert.False(t, got.Flags.RxClosing)

		assert.Equal(t, entry.Packets, got.Packets)
		assert.Equal(t, entry.Bytes, got.Bytes)
		require.NotNil(t, got.Flags)

		require.NotNil(t, got.ExpiresAt)
		assert.True(t, clock.Now.Add(time.Duration(lifetimeDiff)*time.Second).Equal(got.ExpiresAt.AsTime()))
		require.NotNil(t, got.LastTxReportAt)
		assert.True(t, clock.Now.Add(time.Duration(txReportDiff)*time.Second).Equal(got.LastTxReportAt.AsTime()))
		require.NotNil(t, got.LastRxReportAt)
		assert.True(t, clock.Now.Equal(got.LastRxReportAt.AsTime()))

		if isDirIn {
			assert.Equal(t, flowpb.TrafficDirection_INGRESS, got.Direction)
		} else {
			assert.Equal(t, flowpb.TrafficDirection_EGRESS, got.Direction)
		}

		if isTCP {
			require.NotNil(t, got.Tcp)
			assert.Equal(t, uint32(entry.TxFlagsSeen), got.Tcp.TxFlagsSeen)
			assert.Equal(t, uint32(entry.RxFlagsSeen), got.Tcp.RxFlagsSeen)
		} else {
			require.Nil(t, got.Tcp)
		}
	}
}
