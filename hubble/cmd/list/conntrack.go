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

	flowpb "github.com/cilium/cilium/api/v1/flow"
	observerpb "github.com/cilium/cilium/api/v1/observer"
	"github.com/cilium/cilium/hubble/cmd/common/config"
	"github.com/cilium/cilium/hubble/cmd/common/conn"
	"github.com/cilium/cilium/hubble/cmd/common/template"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/u8proto"
)

func newConntrackCommand(vp *viper.Viper) *cobra.Command {
	conntrackCmd := &cobra.Command{
		Use:   "conntrack",
		Short: "List conntrack snapshots",
		Long:  `List the connection tracking snapshots from nodes' conntrack maps.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cancel := context.WithCancel(cmd.Context())
			defer cancel()
			hubbleConn, err := conn.NewWithFlags(ctx, vp)
			if err != nil {
				return err
			}
			defer hubbleConn.Close()
			return runListConntrack(ctx, cmd, hubbleConn)
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

// nodeConntrack groups every conntrack entry streamed for a single node.
// GetConntrackSnapshot streams one entry per message rather than one message
// per node, so the CLI accumulates them here before rendering.
type nodeConntrack struct {
	NodeName   string                       `json:"node_name"`
	ComputedAt time.Time                    `json:"computed_at"`
	Entries    []*observerpb.ConntrackEntry `json:"entries"`
}

func runListConntrack(ctx context.Context, cmd *cobra.Command, conn *grpc.ClientConn) error {
	req := &observerpb.GetConntrackSnapshotRequest{}
	stream, err := observerpb.NewObserverClient(conn).GetConntrackSnapshot(ctx, req)
	if err != nil {
		return err
	}

	var nodes []*nodeConntrack
	var current *nodeConntrack
	for {
		resp, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		if h := resp.GetHeader(); h != nil {
			current = &nodeConntrack{NodeName: h.GetNodeName(), ComputedAt: h.GetComputedAt().AsTime()}
			nodes = append(nodes, current)
			continue
		}
		if ns := resp.GetNodeStatus(); ns != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "Error from node(s) %s: %s\n", strings.Join(ns.GetNodeNames(), ", "), ns.GetMessage())
			continue
		}
		e := resp.GetEntry()
		if e == nil || current == nil {
			continue
		}
		current.Entries = append(current.Entries, e)
	}

	if len(nodes) == 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "No conntrack entries found")
		return nil
	}

	switch listOpts.output {
	case "json":
		return jsonOutput(cmd.OutOrStdout(), nodes)
	case "table":
		return conntrackTableOutput(cmd.OutOrStdout(), nodes)
	default:
		return fmt.Errorf("unknown output format: %s", listOpts.output)
	}
}

func conntrackTableOutput(buf io.Writer, nodes []*nodeConntrack) error {
	tw := tabwriter.NewWriter(buf, 2, 0, 3, ' ', 0)
	fmt.Fprint(tw, "SOURCE\tDESTINATION\tPROTO\tPACKETS\tBYTES\tCONNECTIONS")
	fmt.Fprintln(tw)

	for _, n := range nodes {
		fmt.Fprintf(buf, "Conntrack Snapshot from %s refreshed at %s", n.NodeName, n.ComputedAt.Local())
		fmt.Fprintln(buf)
		for _, v := range sortedEntries(n.Entries) {
			fmt.Fprint(tw,
				fmt.Sprintf("%s %s", v.GetSourceIp(), conntrackEndpointLabel(v.GetSource())), "\t",
				fmt.Sprintf("%s:%d %s", v.GetDestinationIp(), v.GetDestinationPort(), conntrackEndpointLabel(v.GetDestination())), "\t",
				conntrackProtocolName(v.GetProtocol()), "\t",
				v.GetPackets(), "\t",
				v.GetBytes(), "\t",
				v.GetCount(), "\t",
			)
			fmt.Fprintln(tw)
		}
		if err := tw.Flush(); err != nil {
			return err
		}
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
func sortedEntries(entries []*observerpb.ConntrackEntry) []*observerpb.ConntrackEntry {
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
		pi, pj := sortProto(entries[i].GetProtocol()), sortProto(entries[j].GetProtocol())
		if pi != pj {
			return pi < pj
		}
		srcI, srcJ := netip.MustParseAddr(entries[i].GetSourceIp()), netip.MustParseAddr(entries[j].GetSourceIp())
		if c := srcI.Compare(srcJ); c != 0 {
			return c < 0
		}
		dstI, dstJ := netip.MustParseAddr(entries[i].GetDestinationIp()), netip.MustParseAddr(entries[j].GetDestinationIp())
		if c := dstI.Compare(dstJ); c != 0 {
			return c < 0
		}
		return entries[i].GetDestinationPort() < entries[j].GetDestinationPort()
	})
	return entries
}

// conntrackEndpointLabel returns the best human-readable label for the endpoint.
func conntrackEndpointLabel(ep *flowpb.Endpoint) string {
	id := conntrackIdentityLabel(ep)
	name := conntrackEndpointName(ep)
	if name != "" {
		return "(" + name + ", identity=" + id + ")"
	}
	return ""
}

// conntrackEndpointName returns the resolved pod/namespace for an endpoint.
func conntrackEndpointName(ep *flowpb.Endpoint) string {
	if ep == nil {
		return ""
	}
	if ep.GetPodName() != "" {
		if ns := ep.GetNamespace(); ns != "" {
			return ns + "/" + ep.GetPodName()
		}
		return ep.GetPodName()
	}
	if ep.GetNamespace() != "" {
		return ep.GetNamespace()
	}
	if lbls := ep.GetLabels(); len(lbls) == 1 && strings.HasPrefix(lbls[0], "reserved:") {
		return lbls[0]
	}
	return ""
}

// conntrackIdentityLabel renders a reserved identity (e.g. 4) by its name
// (e.g. "health"), using the same convention fmtIdentity uses for `hubble observe`.
func conntrackIdentityLabel(ep *flowpb.Endpoint) string {
	if ep == nil || ep.GetIdentity() == 0 {
		return ""
	}
	numeric := identity.NumericIdentity(ep.GetIdentity())
	if numeric.IsReservedIdentity() {
		return numeric.String()
	}
	return fmt.Sprintf("%d", ep.GetIdentity())
}
