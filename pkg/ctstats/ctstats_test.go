// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ctstats

import (
	"context"
	"errors"
	"maps"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/ctstats/ttlcache"
)

func TestCache(t *testing.T) {
	a := Tuple{Src: netip.MustParseAddr("10.0.0.1"), Dst: netip.MustParseAddr("10.0.0.2"), Proto: 6}
	b := Tuple{Src: netip.MustParseAddr("10.0.0.3"), Dst: netip.MustParseAddr("10.0.0.4"), Proto: 17}

	var calls int
	var fail bool
	live := []Tuple{a, b}
	c := New(func(_ context.Context, yield func(Tuple, Value) bool) error {
		calls++
		if fail {
			return errors.New("boom")
		}
		for _, tuple := range live {
			if !yield(tuple, Value{RxPackets: 1}) {
				break
			}
		}
		return nil
	}, time.Hour, 1)

	s, err := c.Snapshot(t.Context())
	require.NoError(t, err)
	require.Len(t, s.Entries, 2)
	require.True(t, s.Entries[a].Alive)

	// Served from the cache within the ttl.
	s2, err := c.Snapshot(t.Context())
	require.NoError(t, err)
	require.Same(t, s, s2)
	require.Equal(t, 1, calls)

	// Pruned connections surface as not alive on the next refresh, once.
	c.RecordPruned(a, Value{RxPackets: 5})
	live = []Tuple{b}
	c.snapshot = ttlcache.New(0, c.compute)
	s, err = c.Snapshot(t.Context())
	require.NoError(t, err)
	require.False(t, s.Entries[a].Alive)
	require.EqualValues(t, 5, s.Entries[a].RxPackets)
	require.True(t, s.Entries[b].Alive)

	s, err = c.Snapshot(t.Context())
	require.NoError(t, err)
	require.NotContains(t, s.Entries, a)

	// Pruned connections beyond the limit are dropped.
	c.RecordPruned(a, Value{})
	c.RecordPruned(b, Value{})
	require.Len(t, c.pruned, 1)

	// A failed refresh keeps the previous snapshot.
	prev := s
	fail = true
	s, err = c.Snapshot(t.Context())
	require.Error(t, err)
	require.Same(t, prev, s)
}

func TestDeduplicated(t *testing.T) {
	out := Tuple{Src: netip.MustParseAddr("10.0.0.1"), Dst: netip.MustParseAddr("10.0.0.2"), SrcPort: 1, DstPort: 2, Proto: 6}
	in := out
	in.Flags = TupleFlagIn
	require.Equal(t, out, in.Canonical())

	lone := out
	lone.SrcPort = 9
	lone.Flags = TupleFlagIn // IN without OUT counterpart is kept

	svc := out
	svc.Flags = 4 // TUPLE_F_SERVICE is a different hop

	s := &Snapshot{Entries: map[Tuple]Entry{
		out:  {Alive: true},
		in:   {Alive: true},
		lone: {},
		svc:  {},
	}}

	got := maps.Collect(s.Deduplicated())
	require.Len(t, got, 3)
	require.NotContains(t, got, in)

	var nilSnap *Snapshot
	for range nilSnap.Deduplicated() {
		t.Fatal("unexpected entry")
	}
}
