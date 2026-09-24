// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package list

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"google.golang.org/grpc"

	observerpb "github.com/cilium/cilium/api/v1/observer"
	"github.com/cilium/cilium/hubble/cmd/common/config"
	"github.com/cilium/cilium/hubble/cmd/common/conn"
	"github.com/cilium/cilium/hubble/cmd/common/template"
	"github.com/cilium/cilium/pkg/u8proto"
)

func newCTStatsCommand(vp *viper.Viper) *cobra.Command {
	conntrackCmd := &cobra.Command{
		Use:   "conntrack",
		Short: "List conntrack stats",
		Long:  `List the connection tracking stats from nodes' conntrack stats maps.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cancel := context.WithCancel(cmd.Context())
			defer cancel()
			hubbleConn, err := conn.NewWithFlags(ctx, vp)
			if err != nil {
				return err
			}
			defer hubbleConn.Close()
			return runListCTStats(ctx, cmd, hubbleConn)
		},
	}

	formattingFlags := pflag.NewFlagSet("Formatting", pflag.ContinueOnError)
	formattingFlags.StringVarP(
		&listOpts.output, "output", "o", "table",
		`Specify the output format, one of:
 json:     JSON encoding
 table:    Tab-aligned columns`)
	conntrackCmd.Flags().AddFlagSet(formattingFlags)

	conntrackCmd.RegisterFlagCompletionFunc("output", func(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
		return []string{
			"json",
			"table",
		}, cobra.ShellCompDirectiveDefault
	})

	template.RegisterFlagSets(conntrackCmd, formattingFlags, config.ServerFlags)
	return conntrackCmd
}

func runListCTStats(ctx context.Context, cmd *cobra.Command, conn *grpc.ClientConn) error {
	req := &observerpb.GetConntrackStatsRequest{}
	stream, err := observerpb.NewObserverClient(conn).GetConntrackStats(ctx, req)
	if err != nil {
		return err
	}

	var entries []*observerpb.ConntrackStatsEntry
	for {
		resp, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		if ns := resp.GetNodeStatus(); ns != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "Error from node(s) %s: %s\n", strings.Join(ns.GetNodeNames(), ", "), ns.GetMessage())
			continue
		}
		e := resp.GetEntry()
		if e == nil {
			continue
		}
		entries = append(entries, e)
	}

	if len(entries) == 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "No conntrack entries found")
		return nil
	}

	switch listOpts.output {
	case "json":
		return jsonOutput(cmd.OutOrStdout(), entries)
	case "table":
		return conntrackTableOutput(cmd.OutOrStdout(), entries)
	default:
		return fmt.Errorf("unknown output format: %s", listOpts.output)
	}
}

func conntrackTableOutput(buf io.Writer, entries []*observerpb.ConntrackStatsEntry) error {
	tw := tabwriter.NewWriter(buf, 2, 0, 3, ' ', 0)
	fmt.Fprint(tw, "SOURCE\tDESTINATION\tPROTO\tRX PACKETS\tTX PACKETS\tRX BYTES\tTX BYTES")
	fmt.Fprintln(tw)
	for _, v := range sortedEntries(entries) {
		fmt.Fprint(tw,
			fmt.Sprintf("%s:%d", v.GetKey().GetSourceIp(), v.GetKey().GetSourcePort()), "\t",
			fmt.Sprintf("%s:%d", v.GetKey().GetDestinationIp(), v.GetKey().GetDestinationPort()), "\t",
			conntrackProtocolName(v.GetKey().GetProtocol()), "\t",
			v.GetValue().GetRxPackets(), "\t",
			v.GetValue().GetTxPackets(), "\t",
			v.GetValue().GetRxBytes(), "\t",
			v.GetValue().GetTxBytes(), "\t",
		)
		fmt.Fprintln(tw)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	return nil
}

// conntrackProtocolName returns the protocol name for a given protocol number
func conntrackProtocolName(protocol uint32) string {
	if name := u8proto.U8proto(protocol).String(); name != "" {
		return name
	}
	return fmt.Sprintf("%d", protocol)
}

// sortedEntries sorts conntrack entries by protocol order (TCP, UDP, ICMP,
// ICMPv6, then anything else), then by source IP, then by destination
// IP:port (IPv4 addresses sort before IPv6 throughout).
// This is used only for table output.
func sortedEntries(entries []*observerpb.ConntrackStatsEntry) []*observerpb.ConntrackStatsEntry {
	sortProto := func(protocol uint32) int {
		switch u8proto.U8proto(protocol) {
		case u8proto.TCP:
			return 0
		case u8proto.UDP:
			return 1
		case u8proto.ICMP:
			return 2
		case u8proto.ICMPv6:
			return 3
		default:
			return 4
		}
	}
	sort.Slice(entries, func(i, j int) bool {
		pi, pj := sortProto(entries[i].GetKey().GetProtocol()), sortProto(entries[j].GetKey().GetProtocol())
		if pi != pj {
			return pi < pj
		}
		srcI, srcJ := netip.MustParseAddr(entries[i].GetKey().GetSourceIp()), netip.MustParseAddr(entries[j].GetKey().GetSourceIp())
		if c := srcI.Compare(srcJ); c != 0 {
			return c < 0
		}
		dstI, dstJ := netip.MustParseAddr(entries[i].GetKey().GetDestinationIp()), netip.MustParseAddr(entries[j].GetKey().GetDestinationIp())
		if c := dstI.Compare(dstJ); c != 0 {
			return c < 0
		}
		return entries[i].GetKey().GetDestinationPort() < entries[j].GetKey().GetDestinationPort()
	})
	return entries
}
