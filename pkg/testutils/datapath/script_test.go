// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package datapath

import (
	"flag"
	"log/slog"
	"testing"

	"github.com/cilium/hive/hivetest"

	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/testutils/datapath/common"
	"github.com/cilium/cilium/pkg/testutils/datapath/pod"
	"github.com/cilium/cilium/pkg/testutils/datapath/runner"
)

var (
	role     = flag.String("role", common.RunnerRole, "Role for this exec")
	config   = flag.String("config", "", "Config for the child process")
	debug    = flag.Bool("debug", false, "Enable debug logging")
	blocking = flag.Bool("blocking", true, "Allows child process to block, waiting forSIGINT or SIGTERM")
)

func TestPrivilegedDatapathComponent(t *testing.T) {
	var opts []hivetest.LogOption
	if *debug {
		opts = append(opts, hivetest.LogLevel(slog.LevelDebug))
		logging.SetLogLevelToDebug()
	}
	log := hivetest.Logger(t, opts...)
	f := common.NewTestForker(t)

	switch *role {
	case common.PodRole:
		pod.Run(log, t.Context(), *blocking, f, *config)
	case common.NodeRole:
		//node.Run(log, t.Context(), *blocking, f, *config)
	case common.RunnerRole:
		runner.Run(log, t, f)
	default:
		t.Skip("no valid data", *role)
	}
}
