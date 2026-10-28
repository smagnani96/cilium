// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

// Package ctstats converts the datapath conntrack stats cached by ctstats
// into the Hubble conntrack API.
package ctstats

import (
	"iter"

	conntrackpb "github.com/cilium/cilium/api/v1/conntrack"
	"github.com/cilium/cilium/pkg/ctstats"
)

// Entries yields one entry per connection, without the TUPLE_F_IN mirrors (see
// ctstats.Snapshot.Deduplicated).
func Entries(s *ctstats.Snapshot) iter.Seq[*conntrackpb.Entry] {
	return func(yield func(*conntrackpb.Entry) bool) {
		for t, e := range s.Deduplicated() {
			if !yield(toProto(t, e)) {
				return
			}
		}
	}
}

func toProto(t ctstats.Tuple, e ctstats.Entry) *conntrackpb.Entry {
	return &conntrackpb.Entry{
		Key: &conntrackpb.Key{
			SourceIp:        t.Src.String(),
			SourcePort:      uint32(t.SrcPort),
			DestinationIp:   t.Dst.String(),
			DestinationPort: uint32(t.DstPort),
			Protocol:        uint32(t.Proto),
			Flags:           uint32(t.Flags),
		},
		Value: &conntrackpb.Value{
			RxPackets: e.RxPackets,
			TxPackets: e.TxPackets,
			RxBytes:   e.RxBytes,
			TxBytes:   e.TxBytes,
		},
		State: &conntrackpb.State{Alive: e.Alive},
	}
}
