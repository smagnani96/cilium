// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package common

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/time"
)

func TestCache_Hit(t *testing.T) {
	cache := NewCache[string, int](10, time.Minute)

	var calls int
	resolve := func() int {
		calls++
		return 42
	}

	first := cache.GetOrResolve("k", resolve)
	require.Equal(t, 42, first)
	assert.Equal(t, 1, calls, "first call must resolve")

	second := cache.GetOrResolve("k", resolve)
	require.Equal(t, 42, second)
	assert.Equal(t, 1, calls, "second call for the same key must be a cache hit")
}

func TestCache_ExpiresByTTL(t *testing.T) {
	cache := NewCache[string, int](10, time.Millisecond)

	var calls int
	resolve := func() int {
		calls++
		return calls
	}

	cache.GetOrResolve("k", resolve)
	require.Equal(t, 1, calls)

	time.Sleep(20 * time.Millisecond)

	got := cache.GetOrResolve("k", resolve)
	assert.Equal(t, 2, calls, "expired cache entry must trigger a fresh resolve")
	assert.Equal(t, 2, got)
}

func TestCache_CachesNegativeResult(t *testing.T) {
	cache := NewCache[string, *int](10, time.Minute)

	var calls int
	resolve := func() *int {
		calls++
		return nil
	}

	first := cache.GetOrResolve("k", resolve)
	assert.Nil(t, first)

	second := cache.GetOrResolve("k", resolve)
	assert.Nil(t, second)
	assert.Equal(t, 1, calls, "a nil result must be cached too, not re-resolved every call")
}
