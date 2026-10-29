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

	conntrackpb "github.com/cilium/cilium/api/v1/conntrack"
	flowpb "github.com/cilium/cilium/api/v1/flow"
	observerpb "github.com/cilium/cilium/api/v1/observer"
	"github.com/cilium/cilium/hubble/cmd/common/config"
	"github.com/cilium/cilium/hubble/cmd/common/conn"
	"github.com/cilium/cilium/hubble/cmd/common/template"
	"github.com/cilium/cilium/pkg/ctstats"
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

	enrichmentFlags := pflag.NewFlagSet("Enrichment", pflag.ContinueOnError)
	enrichmentFlags.BoolVar(
		&listOpts.serviceEntries, "service-entries", false,
		"Show the service entries as separate rows in the table output, instead of folding them into the connection they belong to")
	conntrackCmd.Flags().AddFlagSet(enrichmentFlags)

	conntrackCmd.RegisterFlagCompletionFunc("output", func(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
		return []string{
			"json",
			"table",
		}, cobra.ShellCompDirectiveDefault
	})

	template.RegisterFlagSets(conntrackCmd, formattingFlags, enrichmentFlags, config.ServerFlags)
	return conntrackCmd
}

func runListCTStats(ctx context.Context, cmd *cobra.Command, conn *grpc.ClientConn) error {
	req := &conntrackpb.GetStatsRequest{}
	stream, err := observerpb.NewObserverClient(conn).GetConntrackStats(ctx, req)
	if err != nil {
		return err
	}

	var (
		entries   []*conntrackpb.Entry
		endpoints []*conntrackpb.IndexedEndpoint
		services  []*conntrackpb.IndexedService
		nodes     []*conntrackpb.IndexedNode
	)
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
			endpoints = append(endpoints, ep)
			continue
		}
		if svc := resp.GetService(); svc != nil {
			services = append(services, svc)
			continue
		}
		if n := resp.GetNode(); n != nil {
			nodes = append(nodes, n)
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
		return jsonOutput(cmd.OutOrStdout(), &conntrackJSONOutput{Endpoints: endpoints, Services: services, Nodes: nodes, Entries: entries})
	case "table":
		return conntrackTableOutput(cmd.OutOrStdout(), entries, endpoints, services, nodes, listOpts.serviceEntries)
	default:
		return fmt.Errorf("unknown output format: %s", listOpts.output)
	}
}

type conntrackJSONOutput struct {
	Endpoints []*conntrackpb.IndexedEndpoint `json:"endpoints,omitempty"`
	Services  []*conntrackpb.IndexedService  `json:"services,omitempty"`
	Nodes     []*conntrackpb.IndexedNode     `json:"nodes,omitempty"`
	Entries   []*conntrackpb.Entry           `json:"entries"`
}

type resolvedByIndex struct {
	endpoints map[uint32]*flowpb.Endpoint
	services  map[uint32]*flowpb.Service
	nodes     map[uint32]*conntrackpb.Node
}

func conntrackTableOutput(
	buf io.Writer,
	entries []*conntrackpb.Entry,
	endpoints []*conntrackpb.IndexedEndpoint,
	services []*conntrackpb.IndexedService,
	nodes []*conntrackpb.IndexedNode,
	serviceEntries bool,
) error {
	byIndex := resolvedByIndex{
		endpoints: make(map[uint32]*flowpb.Endpoint, len(endpoints)),
		services:  make(map[uint32]*flowpb.Service, len(services)),
		nodes:     make(map[uint32]*conntrackpb.Node, len(nodes)),
	}
	for _, ep := range endpoints {
		byIndex.endpoints[ep.GetIndex()] = ep.GetEndpoint()
	}
	for _, svc := range services {
		byIndex.services[svc.GetIndex()] = svc.GetService()
	}
	for _, n := range nodes {
		byIndex.nodes[n.GetIndex()] = n.GetNode()
	}
	var dstServices map[*conntrackpb.Entry]*uint32
	if !serviceEntries {
		entries, dstServices = foldServiceEntries(entries)
	}
	tw := tabwriter.NewWriter(buf, 2, 0, 3, ' ', 0)
	fmt.Fprint(tw, "SOURCE\tDESTINATION\tPROTO\tALIVE\tRX PACKETS\tTX PACKETS\tRX BYTES\tTX BYTES")
	fmt.Fprintln(tw)
	for _, v := range sortedEntries(entries) {
		fmt.Fprint(tw,
			formatAddr(v.GetKey().GetSourceIp(), v.GetKey().GetSourcePort(), v.SourceEndpointIndex, nil, v.SourceNodeIndex, byIndex), "\t",
			formatAddr(v.GetKey().GetDestinationIp(), v.GetKey().GetDestinationPort(), v.DestinationEndpointIndex, dstServiceIndex(v, dstServices), v.DestinationNodeIndex, byIndex), "\t",
			conntrackProtocolName(v.GetKey().GetProtocol()), "\t",
			v.GetState().GetAlive(), "\t",
			v.GetValue().GetRxPackets(), "\t",
			v.GetValue().GetTxPackets(), "\t",
			v.GetValue().GetRxBytes(), "\t",
			v.GetValue().GetTxBytes(),
		)
		fmt.Fprintln(tw)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	return nil
}

func dstServiceIndex(e *conntrackpb.Entry, folded map[*conntrackpb.Entry]*uint32) *uint32 {
	if idx, ok := folded[e]; ok {
		return idx
	}
	return e.DestinationServiceIndex
}

// foldServiceEntries drops the service entries, returning their service as the
// destination service of the entry of the same connection. A service entry
// without exactly one such entry is kept.
func foldServiceEntries(entries []*conntrackpb.Entry) ([]*conntrackpb.Entry, map[*conntrackpb.Entry]*uint32) {
	type connKey struct {
		ip    string
		port  uint32
		proto uint32
	}
	keyOf := func(e *conntrackpb.Entry) connKey {
		k := e.GetKey()
		return connKey{k.GetSourceIp(), k.GetSourcePort(), k.GetProtocol()}
	}
	isService := func(e *conntrackpb.Entry) bool {
		return e.GetKey().GetFlags()&ctstats.TupleFlagService != 0
	}

	conns := make(map[connKey][]*conntrackpb.Entry)
	for _, e := range entries {
		if !isService(e) {
			conns[keyOf(e)] = append(conns[keyOf(e)], e)
		}
	}

	folded := make(map[*conntrackpb.Entry]*uint32)
	kept := make([]*conntrackpb.Entry, 0, len(entries))
	for _, e := range entries {
		if !isService(e) {
			kept = append(kept, e)
			continue
		}
		if c := conns[keyOf(e)]; len(c) == 1 && e.DestinationServiceIndex != nil {
			if prev, ok := folded[c[0]]; !ok || *prev == *e.DestinationServiceIndex {
				folded[c[0]] = e.DestinationServiceIndex
				continue
			}
		}
		kept = append(kept, e)
	}
	return kept, folded
}

func formatAddr(ip string, port uint32, epIdx, svcIdx, nodeIdx *uint32, byIndex resolvedByIndex) string {
	addr := fmt.Sprintf("%s:%d", ip, port)
	var names []string
	if epIdx != nil {
		if name := formatEndpoint(byIndex.endpoints[*epIdx]); name != "" {
			names = append(names, name)
		}
	}
	if svcIdx != nil {
		if svc := byIndex.services[*svcIdx]; svc.GetName() != "" {
			names = append(names, "svc:"+svc.GetNamespace()+"/"+svc.GetName())
		}
	}
	if nodeIdx != nil {
		if n := byIndex.nodes[*nodeIdx]; n.GetName() != "" {
			names = append(names, "node:"+n.GetName())
		}
	}
	if len(names) == 0 {
		return addr
	}
	return addr + " (" + strings.Join(names, ", ") + ")"
}

// formatEndpoint returns the namespace/pod name of ep if known, else its
// reserved identity label, else its endpoint ID. It returns "" for a nil ep.
func formatEndpoint(ep *flowpb.Endpoint) string {
	if ns, pod := ep.GetNamespace(), ep.GetPodName(); ns != "" && pod != "" {
		return ns + "/" + pod
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

func conntrackProtocolName(protocol uint32) string {
	if name := u8proto.U8proto(protocol).String(); name != "" {
		return name
	}
	return fmt.Sprintf("%d", protocol)
}

// sortedEntries sorts the entries by protocol (TCP, UDP, ICMP, ICMPv6, then
// anything else), source IP and destination IP:port.
func sortedEntries(entries []*conntrackpb.Entry) []*conntrackpb.Entry {
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
