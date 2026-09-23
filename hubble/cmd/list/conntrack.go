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
	"google.golang.org/protobuf/types/known/wrapperspb"

	flowpb "github.com/cilium/cilium/api/v1/flow"
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

	endpoints := make(map[uint32]*flowpb.Endpoint)
	nodes := make(map[uint32]*observerpb.ConntrackStatsNode)
	var endpointList []*observerpb.ConntrackStatsEndpoint
	var nodeList []*observerpb.ConntrackStatsNode
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
		if ep := resp.GetEndpoint(); ep != nil {
			endpoints[ep.GetIndex()] = ep.GetEndpoint()
			endpointList = append(endpointList, ep)
			continue
		}
		if n := resp.GetNode(); n != nil {
			nodes[n.GetIndex()] = n
			nodeList = append(nodeList, n)
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
		return jsonOutput(cmd.OutOrStdout(), &conntrackJSONOutput{Endpoints: endpointList, Nodes: nodeList, Entries: entries})
	case "table":
		return conntrackTableOutput(cmd.OutOrStdout(), entries, endpoints, nodes)
	default:
		return fmt.Errorf("unknown output format: %s", listOpts.output)
	}
}

// conntrackJSONOutput is the JSON representation of a GetConntrackStats dump
type conntrackJSONOutput struct {
	Endpoints []*observerpb.ConntrackStatsEndpoint `json:"endpoints,omitempty"`
	Nodes     []*observerpb.ConntrackStatsNode     `json:"nodes,omitempty"`
	Entries   []*observerpb.ConntrackStatsEntry    `json:"entries"`
}

func conntrackTableOutput(buf io.Writer, entries []*observerpb.ConntrackStatsEntry, endpoints map[uint32]*flowpb.Endpoint, nodes map[uint32]*observerpb.ConntrackStatsNode) error {
	tw := tabwriter.NewWriter(buf, 2, 0, 3, ' ', 0)
	fmt.Fprint(tw, "SOURCE\tDESTINATION\tPROTO\tRX PACKETS\tTX PACKETS\tRX BYTES\tTX BYTES")
	fmt.Fprintln(tw)
	for _, v := range sortedEntries(entries) {
		fmt.Fprint(tw,
			formatAddr(v.GetKey().GetSourceIp(), v.GetKey().GetSourcePort(), resolveEndpoint(v.GetSourceEndpointIndex(), endpoints), resolveNode(v.GetSourceNodeIndex(), nodes)), "\t",
			formatAddr(v.GetKey().GetDestinationIp(), v.GetKey().GetDestinationPort(), resolveEndpoint(v.GetDestinationEndpointIndex(), endpoints), resolveNode(v.GetDestinationNodeIndex(), nodes)), "\t",
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

// formatAddr formats an IP address and port, optionally including the resolved data.
func formatAddr(ip string, port uint32, ep *flowpb.Endpoint, node *observerpb.ConntrackStatsNode) string {
	ret := fmt.Sprintf("%s:%d", ip, port)
	if node != nil {
		ret += " (" + formatNode(node) + ")"
	} else if ep != nil {
		ret += " (" + formatEndpoint(ep) + ")"
	}
	return ret
}

// resolveEndpoint looks up idx (if set) in endpoints. A nil idx means the
// server didn't resolve this side of the entry, and must not be confused
// with a resolved index of 0.
func resolveEndpoint(idx *wrapperspb.UInt32Value, endpoints map[uint32]*flowpb.Endpoint) *flowpb.Endpoint {
	if idx == nil {
		return nil
	}
	return endpoints[idx.GetValue()]
}

// resolveNode looks up idx (if set) in nodes. A nil idx means the server
// didn't resolve this side of the entry to a node, and must not be
// confused with a resolved index of 0.
func resolveNode(idx *wrapperspb.UInt32Value, nodes map[uint32]*observerpb.ConntrackStatsNode) *observerpb.ConntrackStatsNode {
	if idx == nil {
		return nil
	}
	return nodes[idx.GetValue()]
}

// formatEndpoint renders ep the same way "hubble observe" renders a flow
// endpoint: namespace/pod name if known, else its reserved identity label,
// else its numeric endpoint ID. Returns "" if ep is nil, i.e. resolution
// failed or wasn't attempted.
func formatEndpoint(ep *flowpb.Endpoint) string {
	if ns, pod := ep.GetNamespace(), ep.GetPodName(); ns != "" && pod != "" {
		return fmt.Sprintf("%s/%s", ns, pod)
	}
	for _, l := range ep.GetLabels() {
		if strings.HasPrefix(l, "reserved:") {
			return l
		}
	}
	if id := ep.GetID(); id != 0 {
		return fmt.Sprintf("ID:%d", id)
	}
	return ""
}

// formatNode renders node as "node/<name>", or "<cluster>/node/<name>" if
// it belongs to a non-local cluster. Returns "" if node is nil, i.e.
// resolution failed or wasn't attempted.
func formatNode(node *observerpb.ConntrackStatsNode) string {
	if cluster := node.GetCluster(); cluster != "" {
		return fmt.Sprintf("%s/node/%s", cluster, node.GetName())
	}
	return fmt.Sprintf("node/%s", node.GetName())
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
