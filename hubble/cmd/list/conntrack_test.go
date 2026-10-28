// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package list

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"

	conntrackpb "github.com/cilium/cilium/api/v1/conntrack"
	flowpb "github.com/cilium/cilium/api/v1/flow"
)

func TestConntrackTableOutput(t *testing.T) {
	entries := []*conntrackpb.Entry{
		{
			Key:                      &conntrackpb.Key{SourceIp: "10.0.0.2", SourcePort: 5353, DestinationIp: "10.0.0.9", DestinationPort: 53, Protocol: 17},
			Value:                    &conntrackpb.Value{RxPackets: 1, TxPackets: 2, RxBytes: 3, TxBytes: 4},
			State:                    &conntrackpb.State{Alive: true},
			SourceEndpointIndex:      new(uint32(0)),
			DestinationEndpointIndex: new(uint32(7)), // never sent
		},
		{
			Key:   &conntrackpb.Key{SourceIp: "10.0.0.1", SourcePort: 1234, DestinationIp: "10.0.0.9", DestinationPort: 80, Protocol: 6},
			Value: &conntrackpb.Value{RxPackets: 5, TxPackets: 6, RxBytes: 7, TxBytes: 8},
		},
	}

	var buf bytes.Buffer
	endpoints := []*conntrackpb.IndexedEndpoint{
		{Index: 0, Endpoint: &flowpb.Endpoint{Namespace: "default", PodName: "web"}},
	}
	require.NoError(t, conntrackTableOutput(&buf, entries, endpoints))

	want := `SOURCE                        DESTINATION   PROTO   ALIVE   RX PACKETS   TX PACKETS   RX BYTES   TX BYTES
10.0.0.1:1234                 10.0.0.9:80   TCP     false   5            6            7          8
10.0.0.2:5353 (default/web)   10.0.0.9:53   UDP     true    1            2            3          4
`
	require.Equal(t, want, buf.String())
}
