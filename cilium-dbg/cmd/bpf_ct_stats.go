// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/spf13/cobra"
)

// BPFCtStatsCmd represents the bpf_ct_stats command
var BPFCtStatsCmd = &cobra.Command{
	Use:   "stats",
	Short: "Connection tracking statistics",
}

func init() {
	BPFCtCmd.AddCommand(BPFCtStatsCmd)
}
