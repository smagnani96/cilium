// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package pod

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/hive/script"
	"github.com/cilium/statedb"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/hive/health"
	"github.com/cilium/cilium/pkg/hive/health/types"
	shell "github.com/cilium/cilium/pkg/shell/server"
	"github.com/cilium/cilium/pkg/testutils/datapath/common"
)

var Cell = cell.Module(
	"pod-cell",
	"Pod cell for datapath component testing",

	shell.Cell,
	cell.Provide(
		newPod,
		scriptCommandsPod,
	),
)

type Pod struct {
	*common.Process

	healthy bool
}

func newPod(p *common.Process) *Pod {
	return &Pod{
		Process: p,
		healthy: true,
	}
}

func scriptCommandsPod(p *Pod) hive.ScriptCmdsOut {
	return hive.NewScriptCmds(map[string]script.Cmd{
		"health": func() script.Cmd {
			return script.Command(
				script.CmdUsage{
					Summary: "Return health status for the pod",
				},
				func(s *script.State, args ...string) (script.WaitFunc, error) {
					return func(s *script.State) (stdout string, stderr string, err error) {
						if p.healthy {
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

func Run(log *slog.Logger, ctx context.Context, blocking bool, f common.Forker, config string) {
	p, err := f.Resume(config)

	h := hive.New(
		Cell,

		health.Cell,
		job.Cell,
		statedb.Cell,
		cell.Provide(
			func(lc cell.Lifecycle, p types.Provider, jr job.Registry) job.Group {
				h := p.ForModule(cell.FullModuleID{"test"})
				return jr.NewGroup(h, lc)
			},
			func() (*common.Process, error) {
				return p, err
			},
		),
		cell.Invoke(
			func(pod *Pod) {
				pod.Process = p
			},
		),
	)
	flags := pflag.NewFlagSet("", pflag.ContinueOnError)
	h.RegisterFlags(flags)
	flags.Set("shell-sock-path", p.ShellSockPath())
	h.Start(log, ctx)

	if blocking {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan
	}
}
