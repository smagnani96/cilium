// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package node

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/script"
	"github.com/spf13/pflag"

	shell "github.com/cilium/cilium/pkg/shell/server"
)

var Cell = cell.Module(
	"node-cell",
	"Node cell for datapath component testing",

	shell.Cell,

	cell.Config(nodeDefaultConfig),
	cell.Provide(
		newNode,
		scriptCommandsNode,
	),
)

var nodeDefaultConfig = NodeConfig{
	Name:  "example-node",
	Iface: "lxc_outer",
}

type NodeConfig struct {
	Name  string
	Iface string
}

func (def NodeConfig) Flags(flags *pflag.FlagSet) {
	flags.String("name", def.Name, "Name of the node")
	flags.String("iface", def.Iface, "Name of the iface")
}

type Node struct {
	config  NodeConfig
	healthy bool
}

func newNode(c NodeConfig) *Node {
	return &Node{
		config:  c,
		healthy: true,
	}
}

func scriptCommandsNode(n *Node) hive.ScriptCmdsOut {
	return hive.NewScriptCmds(map[string]script.Cmd{
		"node/health": func() script.Cmd {
			return script.Command(
				script.CmdUsage{
					Summary: "Simply return the health status",
				},
				func(s *script.State, args ...string) (script.WaitFunc, error) {
					return func(s *script.State) (stdout string, stderr string, err error) {
						if n.healthy {
							stdout = "Health [OK]"
						} else {
							err = fmt.Errorf("Health [KO]")
						}
						return
					}, nil
				})
		}(),
	})
}

func Run(log *slog.Logger, ctx context.Context, blocking bool, config string) {
	h := hive.New(Cell)
	//pflag.CommandLine.ParseErrorsWhitelist.UnknownFlags = true
	fmt.Println("SON QUA")
	h.RegisterFlags(pflag.CommandLine)
	pflag.Parse()
	h.Start(log, ctx)

	if blocking {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan
	}
}
