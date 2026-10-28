// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/maps/ctmap"
)

// bpfCtStatsFlushCmd represents the bpf_ct_stats_flush command
var bpfCtStatsFlushCmd = &cobra.Command{
	Use:   "flush",
	Short: "Flush all connection tracking entries",
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf ct stats flush")
		flushCtStats()
	},
}

func init() {
	BPFCtStatsCmd.AddCommand(bpfCtStatsFlushCmd)
}

func flushCtStats() {
	ipv4, ipv6 := getIpEnableStatuses()

	stats4, stats6 := ctmap.GlobalStatsMaps(ipv4, ipv6)
	for _, statsMap := range []ctmap.StatsMap{stats4, stats6} {
		if err := statsMap.Open(); err != nil {
			continue
		}
		defer statsMap.Close()
		err := statsMap.DeleteAll()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to flush CT stats map %s: %s\n", statsMap.Name(), err)
		} else {
			fmt.Printf("Flushed all entries from CT stats map %s\n", statsMap.Name())
		}
	}
}
