// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ctstats

import (
	"context"

	"github.com/cilium/cilium/pkg/ctstats/ttlcache"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/time"
)

// Cache lazily materializes the Source into a Snapshot, refreshing it at most
// once per ttl.
type Cache struct {
	source    Source
	maxPruned int

	snapshot *ttlcache.Cache[*Snapshot]

	mu     lock.Mutex
	pruned map[Tuple]Value
}

// New returns a Cache keeping at most maxPruned pruned connections between two
// refreshes.
func New(source Source, ttl time.Duration, maxPruned int) *Cache {
	c := &Cache{source: source, maxPruned: maxPruned, pruned: make(map[Tuple]Value)}
	c.snapshot = ttlcache.New(ttl, c.compute)
	return c
}

// Snapshot returns the cached Snapshot, refreshing it if older than the ttl. On
// failure, it returns the previous one (if any) along with the error.
func (c *Cache) Snapshot(ctx context.Context) (*Snapshot, error) {
	return c.snapshot.Get(ctx)
}

// RecordPruned reports a connection removed from the datapath, so that it is
// surfaced as not alive by the next refresh. It is a no-op on a nil Cache.
func (c *Cache) RecordPruned(t Tuple, v Value) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.pruned[t]; ok || len(c.pruned) < c.maxPruned {
		c.pruned[t] = v
	}
}

func (c *Cache) compute(ctx context.Context) (*Snapshot, error) {
	entries := make(map[Tuple]Entry)
	err := c.source(ctx, func(t Tuple, v Value) bool {
		entries[t] = Entry{Value: v, Alive: true}
		return true
	})
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	for t, v := range c.pruned {
		entries[t] = Entry{Value: v}
	}
	clear(c.pruned)
	c.mu.Unlock()

	return &Snapshot{ComputedAt: time.Now(), Entries: entries}, nil
}
