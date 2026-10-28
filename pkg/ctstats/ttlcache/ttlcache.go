// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ttlcache

import (
	"context"
	"sync/atomic"

	"golang.org/x/sync/singleflight"

	"github.com/cilium/cilium/pkg/time"
)

// Cache lazily computes a value, recomputing it at most once per ttl no matter
// how many callers ask for it concurrently.
type Cache[T any] struct {
	ttl     time.Duration
	compute func(ctx context.Context) (T, error)

	cur   atomic.Pointer[computed[T]]
	group singleflight.Group
}

type computed[T any] struct {
	val T
	at  time.Time
}

func New[T any](ttl time.Duration, compute func(ctx context.Context) (T, error)) *Cache[T] {
	return &Cache[T]{ttl: ttl, compute: compute}
}

func (c *Cache[T]) fresh() *computed[T] {
	if v := c.cur.Load(); v != nil && time.Since(v.at) < c.ttl {
		return v
	}
	return nil
}

// Get returns the cached value, recomputing it if older than the ttl. On failure,
// it returns the previous value (if any) along with the error, which is not
// cached. The computation runs with the ctx of the caller that triggered it.
func (c *Cache[T]) Get(ctx context.Context) (T, error) {
	if v := c.fresh(); v != nil {
		return v.val, nil
	}

	ch := c.group.DoChan("", func() (any, error) {
		if c.fresh() != nil {
			return nil, nil
		}
		val, err := c.compute(ctx)
		if err != nil {
			return nil, err
		}
		c.cur.Store(&computed[T]{val: val, at: time.Now()})
		return nil, nil
	})

	var err error
	select {
	case res := <-ch:
		err = res.Err
	case <-ctx.Done():
		err = ctx.Err()
	}

	var val T
	if v := c.cur.Load(); v != nil {
		val = v.val
	}
	return val, err
}
