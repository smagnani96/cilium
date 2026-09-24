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
	for _, s := range []struct {
		enabled bool
		ipv6    bool
		name    string
	}{
		{enabled: ipv4, ipv6: false, name: "ipv4"},
		{enabled: ipv6, ipv6: true, name: "ipv6"},
	} {
		if !s.enabled {
			continue
		}
		m, err := ctmap.OpenStatsMap(log, s.ipv6)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to open CT %s stats map: %s\n", s.name, err)
			continue
		}
		defer m.Close()
		err = m.DeleteAll()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to flush CT %s stats map: %s\n", s.name, err)
			continue
		}
		fmt.Printf("Flushed all entries from CT %s stats map\n", s.name)
	}
}
