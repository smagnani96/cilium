// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/cilium/stream"
	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/maps/nat"
)

// bpfCtFlushCmd represents the bpf_ct_flush command
var bpfCtFlushCmd = &cobra.Command{
	Use:   "flush",
	Short: "Flush all connection tracking entries",
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf ct flush")
		flushCt()
	},
}

func init() {
	BPFCtCmd.AddCommand(bpfCtFlushCmd)
}

func flushCt() {
	ipv4, ipv6 := getIpEnableStatuses()

	nat4, nat6 := nat.GlobalMaps(nil, ipv4, ipv6)
	if nat4 != nil {
		if err := nat4.Open(); err != nil {
			nat4 = nil
		} else {
			defer func() { nat4.Close() }()
		}
	}
	if nat6 != nil {
		if err := nat6.Open(); err != nil {
			nat6 = nil
		} else {
			defer func() { nat6.Close() }()
		}
	}
	ctmap.InitMapInfo(nat4, nat6)

	maps := ctmap.Maps(ipv4, ipv6)

	stats4, stats6 := ctmap.GlobalStatsMaps(ipv4, ipv6)
	if stats4 != nil {
		if err := stats4.Open(); err != nil {
			stats4 = nil
		} else {
			defer stats4.Close()
		}
	}
	if stats6 != nil {
		if err := stats6.Open(); err != nil {
			stats6 = nil
		} else {
			defer stats6.Close()
		}
	}

	observable4, next4, complete4 := stream.Multicast[ctmap.GCEvent]()
	observable6, next6, complete6 := stream.Multicast[ctmap.GCEvent]()
	observable4.Observe(context.Background(), ctmap.NatMapNext4, func(error) {})
	observable6.Observe(context.Background(), ctmap.NatMapNext6, func(error) {})

	if stats4 != nil {
		observable4.Observe(context.Background(), func(event ctmap.GCEvent) { ctmap.PruneStatsEntry(stats4, event, nil) }, func(error) {})
	}
	if stats6 != nil {
		observable6.Observe(context.Background(), func(event ctmap.GCEvent) { ctmap.PruneStatsEntry(stats6, event, nil) }, func(error) {})
	}

	for _, m := range maps {
		path, err := ctmap.OpenCTMap(m)
		if err != nil {
			if os.IsNotExist(err) {
				fmt.Fprintf(os.Stderr, "Unable to open %s: %s. Skipping.\n", path, err)
				continue
			}
			Fatalf("Unable to open %s: %s", path, err)
		}
		defer m.Close()
		entries := m.Flush(next4, next6)
		fmt.Printf("Flushed %d entries from %s\n", entries, path)
	}

	complete4(nil)
	complete6(nil)
}
