// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/maps/ctmap"
)

// bpfCtStatsListCmd represents the bpf_ct_stats_list command
var (
	bpfCtStatsListCmd = &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List connection tracking statistics",
		Run: func(cmd *cobra.Command, args []string) {
			common.RequireRootPrivilege("cilium bpf ct stats list")
			dumpCtStats()
		},
	}
)

func init() {
	BPFCtStatsCmd.AddCommand(bpfCtStatsListCmd)
	command.AddOutputOption(bpfCtStatsListCmd)
}

func dumpCtStats() {
	entries := make([]ctmap.StatsRecord, 0)
	ipv4, ipv6 := getIpEnableStatuses()

	stats4, stats6 := ctmap.GlobalStatsMaps(ipv4, ipv6)
	for _, m := range []ctmap.StatsMap{stats4, stats6} {
		if m == nil {
			continue
		}
		if path, err := ctmap.OpenCTStatsMap(m); err != nil {
			if !os.IsNotExist(err) {
				fmt.Fprintf(os.Stderr, "Unable to open %s: %s\n", path, err)
			}
			continue
		}
		defer m.Close()

		callback := func(key ctmap.StatsKey, value *ctmap.CtStats) bool {
			record := ctmap.StatsRecord{Key: key, Value: value}
			if command.OutputOption() {
				entries = append(entries, record)
			} else {
				var sb strings.Builder
				if err := record.Dump(&sb); err != nil {
					fmt.Fprintf(os.Stderr, "Error while dumping CT stats map %s record %v: %s\n", m.Name(), record, err)
				} else {
					fmt.Println(sb.String())
				}
			}
			return true
		}
		if err := m.DumpWithCallback(callback); err != nil {
			fmt.Fprintf(os.Stderr, "Error while collecting CT Stats BPF map %s entries: %s\n", m.Name(), err)
			continue
		}
	}
	if command.OutputOption() {
		if err := command.PrintOutput(entries); err != nil {
			os.Exit(1)
		}
	}
}
