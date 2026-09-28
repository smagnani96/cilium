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

var ctStatsOpts struct {
	groupBy []string

	sourceIP, destinationIP             []string
	sourcePort, destinationPort         []uint
	protocol                            []string
	sourceEndpoint, destinationEndpoint []string
	sourceNode, destinationNode         []string
}

// groupByFields maps the --group-by flag's user-facing names to the proto
// enum values they select.
var groupByFields = map[string]observerpb.ConntrackAggregationField{
	"source-ip":            observerpb.ConntrackAggregationField_CONNTRACK_AGGREGATION_FIELD_SOURCE_IP,
	"source-port":          observerpb.ConntrackAggregationField_CONNTRACK_AGGREGATION_FIELD_SOURCE_PORT,
	"destination-ip":       observerpb.ConntrackAggregationField_CONNTRACK_AGGREGATION_FIELD_DESTINATION_IP,
	"destination-port":     observerpb.ConntrackAggregationField_CONNTRACK_AGGREGATION_FIELD_DESTINATION_PORT,
	"protocol":             observerpb.ConntrackAggregationField_CONNTRACK_AGGREGATION_FIELD_PROTOCOL,
	"source-endpoint":      observerpb.ConntrackAggregationField_CONNTRACK_AGGREGATION_FIELD_SOURCE_ENDPOINT,
	"destination-endpoint": observerpb.ConntrackAggregationField_CONNTRACK_AGGREGATION_FIELD_DESTINATION_ENDPOINT,
	"source-node":          observerpb.ConntrackAggregationField_CONNTRACK_AGGREGATION_FIELD_SOURCE_NODE,
	"destination-node":     observerpb.ConntrackAggregationField_CONNTRACK_AGGREGATION_FIELD_DESTINATION_NODE,
}

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

	aggregateFlags := pflag.NewFlagSet("Aggregation", pflag.ContinueOnError)
	aggregateFlags.StringSliceVar(
		&ctStatsOpts.groupBy, "group-by", nil,
		fmt.Sprintf(`Aggregate entries server-side by the specified fields.
If unset, every distinct connection is listed individually.
One or more of: %s`, strings.Join(groupByChoices(), ", ")))
	conntrackCmd.Flags().AddFlagSet(aggregateFlags)

	filterFlags := pflag.NewFlagSet("Filtering", pflag.ContinueOnError)
	filterFlags.StringSliceVar(&ctStatsOpts.sourceIP, "source-ip", nil,
		"Show only entries matching this source IP or CIDR (may be repeated)")
	filterFlags.StringSliceVar(&ctStatsOpts.destinationIP, "destination-ip", nil,
		"Show only entries matching this destination IP or CIDR (may be repeated)")
	filterFlags.UintSliceVar(&ctStatsOpts.sourcePort, "source-port", nil,
		"Show only entries matching this source port (may be repeated)")
	filterFlags.UintSliceVar(&ctStatsOpts.destinationPort, "destination-port", nil,
		"Show only entries matching this destination port (may be repeated)")
	filterFlags.StringSliceVar(&ctStatsOpts.protocol, "protocol", nil,
		"Show only entries matching this protocol, e.g. tcp, udp, icmp (may be repeated)")
	filterFlags.StringSliceVar(&ctStatsOpts.sourceEndpoint, "source-endpoint", nil,
		`Show only entries whose resolved source endpoint matches this
"[<namespace>/]<pod-name-prefix>" (may be repeated)`)
	filterFlags.StringSliceVar(&ctStatsOpts.destinationEndpoint, "destination-endpoint", nil,
		`Show only entries whose resolved destination endpoint matches this
"[<namespace>/]<pod-name-prefix>" (may be repeated)`)
	filterFlags.StringSliceVar(&ctStatsOpts.sourceNode, "source-node", nil,
		`Show only entries whose resolved source node matches this
"[<cluster>/]<node-name-prefix>" (may be repeated)`)
	filterFlags.StringSliceVar(&ctStatsOpts.destinationNode, "destination-node", nil,
		`Show only entries whose resolved destination node matches this
"[<cluster>/]<node-name-prefix>" (may be repeated)`)
	conntrackCmd.Flags().AddFlagSet(filterFlags)

	conntrackCmd.RegisterFlagCompletionFunc("output", func(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
		return []string{
			"json",
			"table",
		}, cobra.ShellCompDirectiveDefault
	})
	conntrackCmd.RegisterFlagCompletionFunc("group-by", func(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
		return groupByChoices(), cobra.ShellCompDirectiveDefault
	})

	template.RegisterFlagSets(conntrackCmd, formattingFlags, aggregateFlags, filterFlags, config.ServerFlags)
	return conntrackCmd
}

func groupByChoices() []string {
	choices := make([]string, 0, len(groupByFields))
	for name := range groupByFields {
		choices = append(choices, name)
	}
	sort.Strings(choices)
	return choices
}

// uint32Slice converts a []uint (pflag's UintSlice element type) into
// []uint32, the type ConntrackFilter's port fields use on the wire.
func uint32Slice(vs []uint) []uint32 {
	out := make([]uint32, len(vs))
	for i, v := range vs {
		out[i] = uint32(v)
	}
	return out
}

// parseProtocols converts a list of protocol names (e.g. "tcp", "udp",
// case-insensitive) into their wire protocol numbers.
func parseProtocols(names []string) ([]uint32, error) {
	protocols := make([]uint32, 0, len(names))
	for _, name := range names {
		p, err := u8proto.ParseProtocol(name)
		if err != nil {
			return nil, fmt.Errorf("invalid --protocol value %q: %w", name, err)
		}
		protocols = append(protocols, uint32(p))
	}
	return protocols, nil
}

// buildConntrackFilter builds a *observerpb.ConntrackFilter from listOpts'
// filter flags, or nil if none of them were set.
func buildConntrackFilter() (*observerpb.ConntrackFilter, error) {
	protocols, err := parseProtocols(ctStatsOpts.protocol)
	if err != nil {
		return nil, err
	}

	if len(ctStatsOpts.sourceIP) == 0 && len(ctStatsOpts.destinationIP) == 0 &&
		len(ctStatsOpts.sourcePort) == 0 && len(ctStatsOpts.destinationPort) == 0 &&
		len(protocols) == 0 &&
		len(ctStatsOpts.sourceEndpoint) == 0 && len(ctStatsOpts.destinationEndpoint) == 0 &&
		len(ctStatsOpts.sourceNode) == 0 && len(ctStatsOpts.destinationNode) == 0 {
		return nil, nil
	}

	return &observerpb.ConntrackFilter{
		SourceIp:            ctStatsOpts.sourceIP,
		DestinationIp:       ctStatsOpts.destinationIP,
		SourcePort:          uint32Slice(ctStatsOpts.sourcePort),
		DestinationPort:     uint32Slice(ctStatsOpts.destinationPort),
		Protocol:            protocols,
		SourceEndpoint:      ctStatsOpts.sourceEndpoint,
		DestinationEndpoint: ctStatsOpts.destinationEndpoint,
		SourceNode:          ctStatsOpts.sourceNode,
		DestinationNode:     ctStatsOpts.destinationNode,
	}, nil
}

func parseGroupBy(names []string) ([]observerpb.ConntrackAggregationField, error) {
	fields := make([]observerpb.ConntrackAggregationField, 0, len(names))
	for _, name := range names {
		field, ok := groupByFields[name]
		if !ok {
			return nil, fmt.Errorf("unknown --group-by value %q, must be one of: %s", name, strings.Join(groupByChoices(), ", "))
		}
		fields = append(fields, field)
	}
	return fields, nil
}

func runListCTStats(ctx context.Context, cmd *cobra.Command, conn *grpc.ClientConn) error {
	groupBy, err := parseGroupBy(ctStatsOpts.groupBy)
	if err != nil {
		return err
	}
	filter, err := buildConntrackFilter()
	if err != nil {
		return err
	}
	req := &observerpb.GetConntrackStatsRequest{GroupBy: groupBy, Filter: filter}
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
	fmt.Fprint(tw, "SOURCE\tDESTINATION\tPROTO\tRX PACKETS\tTX PACKETS\tRX BYTES\tTX BYTES\tCOUNT")
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
			v.GetCount(), "\t",
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

// compareIP orders two ConntrackStatsKey source/destination IP strings
// numerically when both are valid addresses (IPv4 before IPv6), or
// lexically otherwise: aggregation can clear a key's IP down to "" when the
// caller didn't group by it, and that's not a parseable address.
func compareIP(a, b string) int {
	addrA, errA := netip.ParseAddr(a)
	addrB, errB := netip.ParseAddr(b)
	if errA != nil || errB != nil {
		return strings.Compare(a, b)
	}
	return addrA.Compare(addrB)
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
		if c := compareIP(entries[i].GetKey().GetSourceIp(), entries[j].GetKey().GetSourceIp()); c != 0 {
			return c < 0
		}
		if c := compareIP(entries[i].GetKey().GetDestinationIp(), entries[j].GetKey().GetDestinationIp()); c != 0 {
			return c < 0
		}
		return entries[i].GetKey().GetDestinationPort() < entries[j].GetKey().GetDestinationPort()
	})
	return entries
}
