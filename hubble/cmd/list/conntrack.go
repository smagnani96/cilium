// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package list

import (
	"context"
	"errors"
	"fmt"
	"io"
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
	"github.com/cilium/cilium/pkg/u8proto"
)

var conntrackOpts struct {
	number uint64
	node   string
	enrich bool

	sourceIP        []string
	destinationIP   []string
	sourcePort      []uint
	destinationPort []uint
	protocol        []string

	sourceIdentity      []uint
	destinationIdentity []uint
	sourcePod           []string
	destinationPod      []string
	service             []string
}

func newConntrackCommand(vp *viper.Viper) *cobra.Command {
	conntrackCmd := &cobra.Command{
		Use:   "conntrack",
		Short: "List conntrack entries",
		Long: `List the connection tracking entries currently present in the datapath
conntrack maps, aggregated across every node behind Hubble Relay.`,
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
	formattingFlags.Uint64VarP(
		&conntrackOpts.number, "number", "n", 0,
		"Maximum number of entries to return per node (default: no limit)")
	formattingFlags.StringVar(
		&conntrackOpts.node, "node", "",
		"Only dump the conntrack table of this node, rather than every node behind Hubble Relay")
	formattingFlags.BoolVar(
		&conntrackOpts.enrich, "enrich", false,
		"Enrich entries with identity, namespace, pod name, service, and node-name info. Has no effect if the agent's hubble-enable-conntrack-enrichment flag is disabled")
	conntrackCmd.Flags().AddFlagSet(formattingFlags)

	filterFlags := pflag.NewFlagSet("Filtering", pflag.ContinueOnError)
	filterFlags.StringSliceVar(
		&conntrackOpts.sourceIP, "source-ip", nil,
		"Only show entries whose source IP matches one of these exact addresses or CIDR ranges (e.g. 10.0.0.1, 10.0.0.0/24)")
	filterFlags.StringSliceVar(
		&conntrackOpts.destinationIP, "destination-ip", nil,
		"Only show entries whose destination IP matches one of these exact addresses or CIDR ranges (e.g. 10.0.0.1, 10.0.0.0/24)")
	filterFlags.UintSliceVar(
		&conntrackOpts.sourcePort, "source-port", nil,
		"Only show entries whose source port matches one of these values")
	filterFlags.UintSliceVar(
		&conntrackOpts.destinationPort, "destination-port", nil,
		"Only show entries whose destination port matches one of these values")
	filterFlags.StringSliceVar(
		&conntrackOpts.protocol, "protocol", nil,
		"Only show entries whose IP protocol matches one of these values (e.g. tcp, udp, icmp)")
	conntrackCmd.Flags().AddFlagSet(filterFlags)

	enrichedFilterFlags := pflag.NewFlagSet("Filtering (requires --enrich)", pflag.ContinueOnError)
	enrichedFilterFlags.UintSliceVar(
		&conntrackOpts.sourceIdentity, "source-identity", nil,
		"Only show entries whose source security identity matches one of these values. Requires --enrich")
	enrichedFilterFlags.UintSliceVar(
		&conntrackOpts.destinationIdentity, "destination-identity", nil,
		"Only show entries whose destination security identity matches one of these values. Requires --enrich")
	enrichedFilterFlags.StringSliceVar(
		&conntrackOpts.sourcePod, "source-pod", nil,
		`Only show entries whose source pod matches one of these namespace/name-prefix values (e.g. "xwing", "kube-system/coredns-", "kube-system/", "/xwing"). Requires --enrich`)
	enrichedFilterFlags.StringSliceVar(
		&conntrackOpts.destinationPod, "destination-pod", nil,
		"Only show entries whose destination pod matches one of these values, following the same convention as --source-pod. Requires --enrich")
	enrichedFilterFlags.StringSliceVar(
		&conntrackOpts.service, "service", nil,
		"Only show entries whose resolved service matches one of these values, following the same convention as --source-pod. Requires --enrich")
	conntrackCmd.Flags().AddFlagSet(enrichedFilterFlags)

	conntrackCmd.RegisterFlagCompletionFunc("output", func(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
		return []string{
			"json",
			"table",
		}, cobra.ShellCompDirectiveDefault
	})

	template.RegisterFlagSets(conntrackCmd, formattingFlags, filterFlags, enrichedFilterFlags, config.ServerFlags)
	return conntrackCmd
}

func runListConntrack(ctx context.Context, cmd *cobra.Command, conn *grpc.ClientConn) error {
	filter, err := newConntrackFilter()
	if err != nil {
		return err
	}
	enrichedFilter := newConntrackEnrichedFilter()
	req := &observerpb.GetConntrackEntriesRequest{
		Number:         conntrackOpts.number,
		NodeName:       conntrackOpts.node,
		Enrich:         conntrackOpts.enrich,
		Filter:         filter,
		EnrichedFilter: enrichedFilter,
	}
	stream, err := observerpb.NewObserverClient(conn).GetConntrackEntries(ctx, req)
	if err != nil {
		return err
	}

	var entries []*observerpb.GetConntrackEntriesResponse
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
		entries = append(entries, resp)
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

// newConntrackFilter builds a ConntrackFilter from the --source-ip,
// --destination-ip, --source-port, --destination-port, and --protocol
// flags. It returns a nil filter if none of them were set.
func newConntrackFilter() (*observerpb.ConntrackFilter, error) {
	if len(conntrackOpts.sourceIP) == 0 && len(conntrackOpts.destinationIP) == 0 &&
		len(conntrackOpts.sourcePort) == 0 && len(conntrackOpts.destinationPort) == 0 &&
		len(conntrackOpts.protocol) == 0 {
		return nil, nil
	}

	protocols := make([]uint32, 0, len(conntrackOpts.protocol))
	for _, p := range conntrackOpts.protocol {
		proto, err := u8proto.ParseProtocol(p)
		if err != nil {
			return nil, fmt.Errorf("invalid --protocol value: %w", err)
		}
		protocols = append(protocols, uint32(proto))
	}

	return &observerpb.ConntrackFilter{
		SourceIp:        conntrackOpts.sourceIP,
		DestinationIp:   conntrackOpts.destinationIP,
		SourcePort:      toUint32s(conntrackOpts.sourcePort),
		DestinationPort: toUint32s(conntrackOpts.destinationPort),
		Protocol:        protocols,
	}, nil
}

// newConntrackEnrichedFilter builds a ConntrackEnrichedFilter from the
// --source-identity, --destination-identity, --source-pod,
// --destination-pod, and --service flags. It returns a nil filter if none of
// them were set.
func newConntrackEnrichedFilter() *observerpb.ConntrackEnrichedFilter {
	if len(conntrackOpts.sourceIdentity) == 0 && len(conntrackOpts.destinationIdentity) == 0 &&
		len(conntrackOpts.sourcePod) == 0 && len(conntrackOpts.destinationPod) == 0 &&
		len(conntrackOpts.service) == 0 {
		return nil
	}

	return &observerpb.ConntrackEnrichedFilter{
		SourceIdentity:      toUint32s(conntrackOpts.sourceIdentity),
		DestinationIdentity: toUint32s(conntrackOpts.destinationIdentity),
		SourcePod:           conntrackOpts.sourcePod,
		DestinationPod:      conntrackOpts.destinationPod,
		Service:             conntrackOpts.service,
	}
}

func toUint32s(vals []uint) []uint32 {
	out := make([]uint32, len(vals))
	for i, v := range vals {
		out[i] = uint32(v)
	}
	return out
}

func conntrackTableOutput(buf io.Writer, entries []*observerpb.GetConntrackEntriesResponse) error {
	tw := tabwriter.NewWriter(buf, 2, 0, 3, ' ', 0)
	fmt.Fprint(tw, "NODE\tSOURCE\tDESTINATION\tPROTO\tPACKETS\tBYTES\tDIRECTION")
	if conntrackOpts.enrich {
		fmt.Fprint(tw, "\tSERVICE\tBACKEND")
	}
	fmt.Fprintln(tw)

	for _, resp := range entries {
		e := resp.GetEntry()
		if e == nil {
			continue
		}

		src := fmt.Sprintf("%s:%d %s", e.GetSourceIp(), e.GetSourcePort(), conntrackEndpointLabel(e.GetSource(), e.GetSourceNodeName()))
		dst := fmt.Sprintf("%s:%d %s", e.GetDestinationIp(), e.GetDestinationPort(), conntrackEndpointLabel(e.GetDestination(), e.GetDestinationNodeName()))

		fmt.Fprint(tw, resp.GetNodeName(), "\t", src, "\t", dst, "\t",
			conntrackProtocolName(e.GetProtocol()), "\t", e.GetPackets(), "\t", e.GetBytes(),
			"\t", e.GetDirection())

		if conntrackOpts.enrich {
			var svc, backend string
			if e.Service != nil {
				svc = fmt.Sprintf("%s/%s", e.Service.GetNamespace(), e.Service.GetName())
			}
			if e.Backend != nil {
				backend = fmt.Sprintf("%s", conntrackEndpointLabel(e.Backend, ""))
			}
			fmt.Fprint(tw, "\t", svc, "\t", backend)
		}

		fmt.Fprintln(tw)
	}
	return tw.Flush()
}

// conntrackProtocolName returns the protocol name for a given protocol number
func conntrackProtocolName(protocol uint32) string {
	if name := u8proto.U8proto(protocol).String(); name != "" {
		return name
	}
	return fmt.Sprintf("%d", protocol)
}

// conntrackEndpointLabel returns the best human-readable label for the endpoint/node.
func conntrackEndpointLabel(ep *flowpb.Endpoint, nodeName string) string {
	id := conntrackIdentityLabel(ep)
	name := conntrackEndpointName(ep)
	if name != "" {
		return "(" + name + ", identity=" + id + ")"
	}
	if nodeName != "" {
		return "(" + nodeName + ", identity=" + id + ")"
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
