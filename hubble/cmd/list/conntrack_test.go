// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package list

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"

	conntrackpb "github.com/cilium/cilium/api/v1/conntrack"
	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/ctstats"
)

func TestConntrackTableOutput(t *testing.T) {
	entries := []*conntrackpb.Entry{
		{
			Key:                      &conntrackpb.Key{SourceIp: "10.0.0.2", SourcePort: 5353, DestinationIp: "10.0.0.9", DestinationPort: 53, Protocol: 17},
			Value:                    &conntrackpb.Value{RxPackets: 1, TxPackets: 2, RxBytes: 3, TxBytes: 4},
			State:                    &conntrackpb.State{Alive: true},
			SourceEndpointIndex:      new(uint32(0)),
			DestinationEndpointIndex: new(uint32(7)), // never sent
			DestinationServiceIndex:  new(uint32(7)), // never sent
		},
		{
			Key:                      &conntrackpb.Key{SourceIp: "10.0.0.1", SourcePort: 1234, DestinationIp: "10.0.0.9", DestinationPort: 80, Protocol: 6},
			Value:                    &conntrackpb.Value{RxPackets: 5, TxPackets: 6, RxBytes: 7, TxBytes: 8},
			DestinationEndpointIndex: new(uint32(0)),
			DestinationServiceIndex:  new(uint32(0)),
		},
		{
			Key:                     &conntrackpb.Key{SourceIp: "10.0.0.3", SourcePort: 99, DestinationIp: "10.96.0.1", DestinationPort: 443, Protocol: 6},
			Value:                   &conntrackpb.Value{},
			DestinationServiceIndex: new(uint32(0)),
		},
	}

	var buf bytes.Buffer
	endpoints := []*conntrackpb.IndexedEndpoint{
		{Index: 0, Endpoint: &flowpb.Endpoint{Namespace: "default", PodName: "web"}},
	}
	services := []*conntrackpb.IndexedService{
		{Index: 0, Service: &flowpb.Service{Namespace: "default", Name: "web"}},
	}
	require.NoError(t, conntrackTableOutput(&buf, entries, endpoints, services, false))

	want := `SOURCE                        DESTINATION                                  PROTO   ALIVE   RX PACKETS   TX PACKETS   RX BYTES   TX BYTES
10.0.0.1:1234                 10.0.0.9:80 (default/web, svc:default/web)   TCP     false   5            6            7          8
10.0.0.3:99                   10.96.0.1:443 (svc:default/web)              TCP     false   0            0            0          0
10.0.0.2:5353 (default/web)   10.0.0.9:53                                  UDP     true    1            2            3          4
`
	require.Equal(t, want, buf.String())
}

func TestConntrackTableOutputServiceEntries(t *testing.T) {
	entries := []*conntrackpb.Entry{
		// The service entry, and the entry of the same connection to the backend.
		{
			Key:                     &conntrackpb.Key{SourceIp: "10.0.0.1", SourcePort: 1000, DestinationIp: "10.96.0.1", DestinationPort: 80, Protocol: 6, Flags: ctstats.TupleFlagService},
			Value:                   &conntrackpb.Value{TxPackets: 6},
			DestinationServiceIndex: new(uint32(0)),
		},
		{
			Key:   &conntrackpb.Key{SourceIp: "10.0.0.1", SourcePort: 1000, DestinationIp: "10.0.1.5", DestinationPort: 8080, Protocol: 6},
			Value: &conntrackpb.Value{RxPackets: 4, TxPackets: 6},
		},
		// A service entry with no matching connection is kept.
		{
			Key:                     &conntrackpb.Key{SourceIp: "10.0.0.2", SourcePort: 2000, DestinationIp: "10.96.0.1", DestinationPort: 80, Protocol: 6, Flags: ctstats.TupleFlagService},
			Value:                   &conntrackpb.Value{},
			DestinationServiceIndex: new(uint32(0)),
		},
	}
	services := []*conntrackpb.IndexedService{
		{Index: 0, Service: &flowpb.Service{Namespace: "default", Name: "web"}},
	}

	var buf bytes.Buffer
	require.NoError(t, conntrackTableOutput(&buf, entries, nil, services, false))
	want := `SOURCE          DESTINATION                       PROTO   ALIVE   RX PACKETS   TX PACKETS   RX BYTES   TX BYTES
10.0.0.1:1000   10.0.1.5:8080 (svc:default/web)   TCP     false   4            6            0          0
10.0.0.2:2000   10.96.0.1:80 (svc:default/web)    TCP     false   0            0            0          0
`
	require.Equal(t, want, buf.String())

	buf.Reset()
	require.NoError(t, conntrackTableOutput(&buf, entries, nil, services, true))
	want = `SOURCE          DESTINATION                      PROTO   ALIVE   RX PACKETS   TX PACKETS   RX BYTES   TX BYTES
10.0.0.1:1000   10.0.1.5:8080                    TCP     false   4            6            0          0
10.0.0.1:1000   10.96.0.1:80 (svc:default/web)   TCP     false   0            6            0          0
10.0.0.2:2000   10.96.0.1:80 (svc:default/web)   TCP     false   0            0            0          0
`
	require.Equal(t, want, buf.String())
}
