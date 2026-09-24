// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/logging/logfields"
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
	ipv4, ipv6 := getIpEnableStatuses()
	entries := make([]ctmap.StatsRecord, 0)

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

		callback := func(key bpf.MapKey, values any) {
			v := values.(*ctmap.StatsValues)
			record := ctmap.StatsRecord{Key: key.(ctmap.CtKey), Value: v.Aggregate()}
			if command.OutputOption() {
				entries = append(entries, record)
			} else {
				printCtStatsRecord(record)
			}
		}
		if err = m.DumpPerCPUWithCallback(callback); err != nil {
			fmt.Fprintf(os.Stderr, "Error while collecting CT Stats %s BPF map entries: %s\n", s.name, err)
			continue
		}
	}
	if command.OutputOption() {
		if err := command.PrintOutput(entries); err != nil {
			os.Exit(1)
		}
	}
}

func printCtStatsRecord(r ctmap.StatsRecord) {
	var sb strings.Builder
	if !r.Key.ToHost().Dump(&sb, true) {
		log.Error("Failed to dump CT stats record", logfields.Error, fmt.Errorf("unable to dump key: %s", sb.String()))
		return
	}
	fmt.Printf("%s RxPackets=%d RxBytes=%d TxPackets=%d TxBytes=%d",
		sb.String(), r.Value.RxPackets, r.Value.RxBytes, r.Value.TxPackets, r.Value.TxBytes)
	fmt.Println()
}
