// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package ctstats

import "iter"

// Dedup assigns a stable index to each distinct value, as told apart by keyOf,
// so that a stream carries it once and the entries share it by reference.
type Dedup[K, V comparable] struct {
	keyOf func(V) K
	byKey map[K]uint32
	list  []V
}

func newDedup[K, V comparable](keyOf func(V) K) *Dedup[K, V] {
	return &Dedup[K, V]{keyOf: keyOf, byKey: make(map[K]uint32)}
}

// Index returns the index of v, allocating it if v is new. The first value
// seen for a given key is the one kept. It returns false if v is the zero
// value, e.g. a nil pointer.
func (d *Dedup[K, V]) Index(v V) (uint32, bool) {
	var zero V
	if v == zero {
		return 0, false
	}
	k := d.keyOf(v)
	if idx, ok := d.byKey[k]; ok {
		return idx, true
	}
	idx := uint32(len(d.list))
	d.byKey[k] = idx
	d.list = append(d.list, v)
	return idx, true
}

func (d *Dedup[K, V]) All() iter.Seq2[uint32, V] {
	return func(yield func(uint32, V) bool) {
		for i, v := range d.list {
			if !yield(uint32(i), v) {
				return
			}
		}
	}
}
