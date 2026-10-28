// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ctmap

import (
	"context"
	"errors"

	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/maps/nat"
	"github.com/cilium/cilium/pkg/tuple"
)

// NOTE: the function does NOT copy addr fields, so it's not safe to
// reuse the returned ctKey.
func dsrCTKeyFromEgressNatKey(k nat.NatKey) bpf.MapKey {
	natKey, ok := k.(*nat.NatKey4)
	if ok { // ipv4
		t := tuple.TupleKey4{
			SourceAddr: natKey.DestAddr,
			SourcePort: natKey.DestPort,
			DestAddr:   natKey.SourceAddr,
			DestPort:   natKey.SourcePort,
			NextHeader: natKey.NextHeader,
			Flags:      tuple.TUPLE_F_OUT,
		}

		// Workaround #5848
		t.SwapAddresses()

		return &tuple.TupleKey4Global{TupleKey4: t}
	}

	{ // ipv6
		natKey := k.(*nat.NatKey6)

		t := tuple.TupleKey6{
			SourceAddr: natKey.DestAddr,
			SourcePort: natKey.DestPort,
			DestAddr:   natKey.SourceAddr,
			DestPort:   natKey.SourcePort,
			NextHeader: natKey.NextHeader,
			Flags:      tuple.TUPLE_F_OUT,
		}

		// Workaround #5848
		t.SwapAddresses()

		return &tuple.TupleKey6Global{TupleKey6: t}
	}
}

// NOTE: the function does NOT copy addr fields, so it's not safe to
// reuse the returned ctKey.
func egressCTKeyFromIngressNatKeyAndVal(k nat.NatKey, v nat.NatEntry) bpf.MapKey {
	natKey, ok := k.(*nat.NatKey4)
	if ok { // ipv4
		natVal := v.(*nat.NatEntry4)

		t := tuple.TupleKey4{
			SourceAddr: natVal.Addr,
			SourcePort: natVal.Port,
			DestAddr:   natKey.SourceAddr,
			DestPort:   natKey.SourcePort,
			NextHeader: natKey.NextHeader,
			Flags:      tuple.TUPLE_F_OUT,
		}

		// Workaround #5848
		t.SwapAddresses()

		return &tuple.TupleKey4Global{TupleKey4: t}
	}

	{ // ipv6
		natKey := k.(*nat.NatKey6)
		natVal := v.(*nat.NatEntry6)

		t := tuple.TupleKey6{
			SourceAddr: natVal.Addr,
			SourcePort: natVal.Port,
			DestAddr:   natKey.SourceAddr,
			DestPort:   natKey.SourcePort,
			NextHeader: natKey.NextHeader,
			Flags:      tuple.TUPLE_F_OUT,
		}

		// Workaround #5848
		t.SwapAddresses()

		return &tuple.TupleKey6Global{TupleKey6: t}
	}
}

// NOTE: the function does NOT copy addr fields, so it's not safe to
// reuse the returned ctKey.
func egressCTKeyFromEgressNatKey(k nat.NatKey) bpf.MapKey {
	natKey, ok := k.(*nat.NatKey4)
	if ok { // ipv4
		t := tuple.TupleKey4{
			SourceAddr: natKey.SourceAddr,
			SourcePort: natKey.SourcePort,
			DestAddr:   natKey.DestAddr,
			DestPort:   natKey.DestPort,
			NextHeader: natKey.NextHeader,
			Flags:      tuple.TUPLE_F_OUT,
		}

		// Workaround #5848
		t.SwapAddresses()

		return &tuple.TupleKey4Global{TupleKey4: t}
	}

	{ // ipv6
		natKey := k.(*nat.NatKey6)

		t := tuple.TupleKey6{
			SourceAddr: natKey.SourceAddr,
			SourcePort: natKey.SourcePort,
			DestAddr:   natKey.DestAddr,
			DestPort:   natKey.DestPort,
			NextHeader: natKey.NextHeader,
			Flags:      tuple.TUPLE_F_OUT,
		}

		// Workaround #5848
		t.SwapAddresses()

		return &tuple.TupleKey6Global{TupleKey6: t}
	}
}

func ctEntryExist(ctMap *Map, ctKey bpf.MapKey, f func(*CtEntry) bool) bool {
	v, err := ctMap.Lookup(ctKey)

	if err != nil {
		return !errors.Is(err, unix.ENOENT)
	}

	if f == nil {
		return true
	}

	return f(v.(*CtEntry))
}

// iterate iterates over all entries in the given BPF map (non per-CPU) and
// applies the filterCallback to each key-value pair.
func iterate[KT any, VT any, KP bpf.KeyPointer[KT], VP bpf.ValuePointer[VT]](m *bpf.Map, filterCallback func(key bpf.MapKey, value bpf.MapValue)) error {
	ctx := context.Background()
	seq, errFn := bpf.BatchIterate[KT, VT, KP, VP](ctx, m)
	for k, v := range seq {
		filterCallback(k, v)
	}
	return errFn()
}
