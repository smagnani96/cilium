// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package common

import (
	lru "github.com/hashicorp/golang-lru/v2"

	"github.com/cilium/cilium/pkg/time"
)

// Cache is a size-bounded, TTL-evicted cache for a single resolved entity
// type (endpoint, service, node name, ...), keyed by whatever uniquely
// identifies that entity (an address, a service ID).
// Entries are evicted by TTL (checked on read, not swept in the background)
// and bounded by an LRU cap so an entity that disappears (e.g. a Pod
// deleted) without us observing it doesn't linger forever.
type Cache[K comparable, V any] struct {
	cache *lru.Cache[K, cacheEntry[V]]
	ttl   time.Duration
}

type cacheEntry[V any] struct {
	resolvedAt time.Time
	value      V
}

func NewCache[K comparable, V any](size int, ttl time.Duration) *Cache[K, V] {
	cache, err := lru.New[K, cacheEntry[V]](size)
	if err != nil {
		panic(err)
	}
	return &Cache[K, V]{cache: cache, ttl: ttl}
}

// GetOrResolve returns the cached value for key if present and not expired,
// otherwise calls resolve, caches its result, and returns it. This also
// caches a "nothing found" result (e.g. resolve returning a nil *Endpoint).
func (c *Cache[K, V]) GetOrResolve(key K, resolve func() V) V {
	if e, ok := c.cache.Get(key); ok && time.Since(e.resolvedAt) <= c.ttl {
		return e.value
	}
	v := resolve()
	c.cache.Add(key, cacheEntry[V]{resolvedAt: time.Now(), value: v})
	return v
}

// Reset discards every cached entry, immediately turning every subsequent
// GetOrResolve call into a fresh resolve regardless of TTL. Useful for
// test/benchmark code that wants to measure a cold-cache scenario.
func (c *Cache[K, V]) Reset() {
	c.cache.Purge()
}
