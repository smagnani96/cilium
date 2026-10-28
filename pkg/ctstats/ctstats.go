// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package ctstats provides a userspace cache of the per-connection packet and
// byte counters accounted by the datapath.
package ctstats

import (
	"context"
	"iter"
	"net/netip"

	"github.com/cilium/cilium/pkg/time"
)

// TupleFlagIn and TupleFlagService are the TUPLE_F_IN and TUPLE_F_SERVICE bits
// of Tuple.Flags. They must match the ctmap ones.
const (
	TupleFlagIn      = 1
	TupleFlagService = 4
)

type Tuple struct {
	Src, Dst         netip.Addr
	SrcPort, DstPort uint16
	Proto            uint8
	Flags            uint8
}

// Canonical returns the tuple with TUPLE_F_IN cleared, as the mirrored entries
// of a connection differ only by it. TUPLE_F_SERVICE and TUPLE_F_RELATED are
// kept, as they identify different hops.
func (t Tuple) Canonical() Tuple {
	t.Flags &^= TupleFlagIn
	return t
}

type Value struct {
	RxPackets, RxBytes uint64
	TxPackets, TxBytes uint64
}

func (v *Value) Add(other Value) {
	v.RxPackets += other.RxPackets
	v.RxBytes += other.RxBytes
	v.TxPackets += other.TxPackets
	v.TxBytes += other.TxBytes
}

func (v *Value) Max(other Value) {
	v.RxPackets = max(v.RxPackets, other.RxPackets)
	v.RxBytes = max(v.RxBytes, other.RxBytes)
	v.TxPackets = max(v.TxPackets, other.TxPackets)
	v.TxBytes = max(v.TxBytes, other.TxBytes)
}

type Entry struct {
	Value
	// Alive is false for connections that were pruned since the previous
	// Snapshot, carrying their last known counters.
	Alive bool
}

type Snapshot struct {
	ComputedAt time.Time
	Entries    map[Tuple]Entry
}

// Deduplicated yields every connection of the snapshot once, keeping only the
// canonical entry of those observed with opposite TUPLE_F_IN/TUPLE_F_OUT flags.
func (s *Snapshot) Deduplicated() iter.Seq2[Tuple, Entry] {
	return func(yield func(Tuple, Entry) bool) {
		if s == nil {
			return
		}
		for t, e := range s.Entries {
			if t.Flags&TupleFlagIn != 0 {
				if _, ok := s.Entries[t.Canonical()]; ok {
					continue
				}
			}
			if !yield(t, e) {
				return
			}
		}
	}
}

// Source walks the datapath, yielding every connection until yield returns false.
type Source func(ctx context.Context, yield func(Tuple, Value) bool) error
