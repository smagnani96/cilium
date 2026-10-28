// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package ctstats

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/ctstats"
)

func TestEntries(t *testing.T) {
	tuple := func(flags uint8) ctstats.Tuple {
		return ctstats.Tuple{
			Src: netip.MustParseAddr("10.0.0.1"), Dst: netip.MustParseAddr("10.0.0.2"),
			SrcPort: 1234, DstPort: 80, Proto: 6, Flags: flags,
		}
	}
	other := tuple(0)
	other.SrcPort = 4321

	snap := &ctstats.Snapshot{Entries: map[ctstats.Tuple]ctstats.Entry{
		tuple(0):                   {Value: ctstats.Value{TxPackets: 3}, Alive: true},
		tuple(ctstats.TupleFlagIn): {Value: ctstats.Value{RxPackets: 3}, Alive: true}, // mirror
		other:                      {Value: ctstats.Value{TxBytes: 7}},
		func() ctstats.Tuple { // IN without OUT counterpart is kept
			x := other
			x.SrcPort = 1
			x.Flags = ctstats.TupleFlagIn
			return x
		}(): {Alive: true},
	}}

	got := slices.Collect(Entries(snap))
	require.Len(t, got, 3)

	var seen int
	for _, e := range got {
		switch e.Key.SourcePort {
		case 1234:
			seen++
			require.Zero(t, e.Key.Flags)
			require.EqualValues(t, 3, e.Value.TxPackets)
			require.True(t, e.State.Alive)
			require.Equal(t, "10.0.0.1", e.Key.SourceIp)
		case 4321:
			seen++
			require.False(t, e.State.Alive)
			require.EqualValues(t, 7, e.Value.TxBytes)
		}
	}
	require.Equal(t, 2, seen)

	require.Empty(t, slices.Collect(Entries(nil)))
}
