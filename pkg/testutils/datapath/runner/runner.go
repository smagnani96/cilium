// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package runner

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"os"
	"regexp"
	"testing"
	"time"

	"github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/hive/script"
	"github.com/cilium/hive/script/scripttest"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/cilium/cilium/pkg/hive/health/types"
	shell "github.com/cilium/cilium/pkg/shell/client"
	common "github.com/cilium/cilium/pkg/testutils/datapath/common"
)

var Cell = cell.Module(
	"runner-cell",
	"Runner cell for datapath component testing",

	cell.Provide(
		newRunner,
		scriptCommandsRunner,
	),
)

type Runner struct {
	procs map[string]map[string]*common.Process

	config *common.TestConfig
}

func newRunner() *Runner {
	return &Runner{
		procs: map[string]map[string]*common.Process{
			common.PodRole:  {},
			common.NodeRole: {},
		},
	}
}

func scriptCommandsRunner(r *Runner, f common.Forker) hive.ScriptCmdsOut {
	return hive.NewScriptCmds(map[string]script.Cmd{
		"setup": func() script.Cmd {
			return script.Command(
				script.CmdUsage{
					Summary: "Setup the instance",
				},
				func(s *script.State, args ...string) (script.WaitFunc, error) {
					return func(s *script.State) (stdout string, stderr string, err error) {
						data, err := os.ReadFile(s.Path(args[0]))
						if err != nil {
							return
						}

						dec := yaml.NewDecoder(bytes.NewReader(data))
						dec.KnownFields(true)

						var config common.TestConfig
						if err = dec.Decode(&config); err != nil {
							return
						}
						r.config = &config

						for _, pod := range config.Pods {
							var p *common.Process
							p, err = f.Fork(common.PodRole, pod.Name, io.Discard, io.Discard)
							if err != nil {
								err = fmt.Errorf("Failed to fork: %w", err)
								return
							}
							r.procs[common.PodRole][p.Name] = p
						}

						for _, node := range config.Nodes {
							var p *common.Process
							p, err = f.Fork(common.PodRole, node.Name, io.Discard, io.Discard)
							if err != nil {
								err = fmt.Errorf("Failed to fork: %w", err)
								return
							}
							r.procs[common.NodeRole][p.Name] = p
						}

						return
					}, nil
				})
		}(),
		common.PodRole:  r.proxyFor(common.PodRole)(),
		common.NodeRole: r.proxyFor(common.NodeRole)(),
	})
}

func (r *Runner) proxyFor(role string) func() script.Cmd {
	return func() script.Cmd {
		return script.Command(
			script.CmdUsage{
				Summary: fmt.Sprintf("Proxy for script %s/x commands", role),
			},
			func(s *script.State, args ...string) (script.WaitFunc, error) {
				return func(s *script.State) (stdout string, stderr string, err error) {
					if len(args) < 2 {
						err = fmt.Errorf("Cannot proxy command for %s with not enough args! Needs target and command.", role)
						return
					}

					var (
						buf      bytes.Buffer
						w        io.Writer = &buf
						target             = args[0]
						cmd                = args[1]
						sockPath           = r.procs[role][target].ShellSockPath()
					)

					err = shell.ShellExchangePath(w, sockPath, cmd)
					if err != nil {
						err = fmt.Errorf("Error proxying command %s: %w", cmd, err)
						return
					}

					errs := regexp.
						MustCompile(fmt.Sprintf(`<stdin>:0: %s:\s*(.*)`, regexp.QuoteMeta(cmd))).
						FindSubmatch(buf.Bytes())
					if len(errs) > 1 {
						err = fmt.Errorf("Failed operation in target %s with following errors:\n", role)
						for _, e := range errs {
							err = errors.Join(err, fmt.Errorf("-> %s", e))
						}
					} else {
						stdout = fmt.Sprintf("Operation Succeeded in target %s: %s", role, buf.String())
					}
					return
				}, nil
			})
	}
}

func Run(log *slog.Logger, t *testing.T, f common.Forker) {
	setup := func(tb testing.TB, args []string) *script.Engine {
		h := hive.New(
			Cell,
			cell.Provide(
				func() common.Forker { return f },
				func(lc cell.Lifecycle, p types.Provider, jr job.Registry) job.Group {
					h := p.ForModule(cell.FullModuleID{"test"})
					return jr.NewGroup(h, lc)
				},
			),
		)

		cmds, err := h.ScriptCommands(log)
		require.NoError(tb, err, "ScriptCommands")
		maps.Insert(cmds, maps.All(script.DefaultCmds()))

		return &script.Engine{
			Cmds:             cmds,
			RetryInterval:    100 * time.Millisecond,
			MaxRetryInterval: time.Second,
		}
	}

	scripttest.Test(t,
		t.Context(),
		setup,
		[]string{},
		"testdata/*.txtar")
}
