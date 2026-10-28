// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ttlcache

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCache(t *testing.T) {
	var calls int
	fail := false
	c := New(time.Hour, func(context.Context) (int, error) {
		calls++
		if fail {
			return 0, errors.New("boom")
		}
		return calls, nil
	})

	for range 3 {
		v, err := c.Get(t.Context())
		require.NoError(t, err)
		require.Equal(t, 1, v)
	}
	require.Equal(t, 1, calls)

	// On failure the previous value is returned along with the error, and
	// the error is not cached.
	c.ttl = 0
	fail = true
	v, err := c.Get(t.Context())
	require.Error(t, err)
	require.Equal(t, 1, v)

	fail = false
	v, err = c.Get(t.Context())
	require.NoError(t, err)
	require.Equal(t, 3, v)
}
