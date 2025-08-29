// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package common

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"syscall"

	"github.com/cilium/cilium/pkg/defaults"
)

type Process struct {
	ProcessParams `yaml:"processParams" json:"processParams"`

	Cmd *exec.Cmd `yaml:"-" json:"-"`
}

type ProcessParams struct {
	Role      string    `yaml:"role" json:"role"`
	Name      string    `yaml:"name" json:"name"`
	CmdString string    `yaml:"cmdString" json:"cmdString"`
	Args      []string  `yaml:"args" json:"args"`
	Stdout    io.Writer `yaml:"-" json:"-"`
	Stderr    io.Writer `yaml:"-" json:"-"`
}

func NewProcess(params ProcessParams) *Process {
	p := exec.Command(params.CmdString, params.Args...)

	p.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWNET | syscall.CLONE_NEWUTS | syscall.CLONE_NEWPID | syscall.CLONE_NEWNS,
	}

	p.Stdout = params.Stdout
	p.Stderr = params.Stderr

	return &Process{
		ProcessParams: params,
		Cmd:           p,
	}
}

func (p *Process) NSMountPath() string {
	return fmt.Sprintf("/var/run/netns/%s-%s", p.Role, p.Name)
}

func (p *Process) nsPath() string {
	return fmt.Sprintf("/proc/%d/ns/net", p.Cmd.Process.Pid)
}

func (p *Process) MoveNs() error {
	if err := os.MkdirAll("/var/run/netns", 0755); err != nil {
		return fmt.Errorf("Process %s Netns setup failed: %w", p.Role, err)
	}

	f, err := os.OpenFile(p.NSMountPath(), os.O_CREATE|os.O_RDONLY, 0644)
	if err != nil {
		return fmt.Errorf("Process %s Netns create failed: %w", p.Role, err)
	}
	defer f.Close()

	if err := syscall.Mount(p.nsPath(), p.NSMountPath(), "none", syscall.MS_BIND, ""); err != nil {
		return fmt.Errorf("Process %s Netns bind failed: %w", p.Role, err)
	}

	return nil
}

func (p *Process) ShellSockPath() string {
	return fmt.Sprintf("%s-%s-%s", defaults.ShellSockPath, p.Role, p.Name)
}
