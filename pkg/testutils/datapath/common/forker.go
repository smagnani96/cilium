// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package common

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"gopkg.in/yaml.v3"
)

type Forker interface {
	Fork(role, name string, stdout, stderr io.Writer) (*Process, error)
	Resume(config string) (*Process, error)
}

type TestForker struct {
	tb testing.TB
}

func NewTestForker(tb testing.TB) *TestForker {
	return &TestForker{tb}
}

func (tf *TestForker) Fork(role, name string, stdout, stderr io.Writer) (*Process, error) {
	config := filepath.Join(tf.tb.TempDir(), "config.yaml")

	params := ProcessParams{
		Role:      role,
		Name:      name,
		Stdout:    stdout,
		Stderr:    stderr,
		CmdString: os.Args[0],
		Args:      os.Args[1:],
	}
	params.Args = append(params.Args, fmt.Sprintf("-test.run=%s$", tf.tb.Name()))
	params.Args = append(params.Args, fmt.Sprintf("--role=%s", role))
	params.Args = append(params.Args, fmt.Sprintf("--config=%s", config))
	params.Args = append(params.Args, "--blocking")

	p := NewProcess(params)
	// Marshal struct to YAML
	data, err := yaml.Marshal(p)
	if err != nil {
		tf.tb.Fatalf("Error marshalling to YAML: %v", err)
	}

	// Write YAML to file
	err = os.WriteFile(config, data, 0644)
	if err != nil {
		tf.tb.Fatalf("Error writing YAML file: %v", err)
	}

	if err := p.Cmd.Start(); err != nil {
		tf.tb.Fatalf("Process %s signal failed: %v", params.Role, err)
	}

	tf.tb.Cleanup(func() {
		if err := p.Cmd.Process.Signal(syscall.SIGINT); err != nil {
			tf.tb.Fatalf("Process %s signal failed: %v", params.Role, err)
		}
		if err := p.Cmd.Wait(); err != nil {
			tf.tb.Fatalf("Process %s wait failed: %v", params.Role, err)
		}
	})

	err = p.MoveNs()
	if err != nil {
		tf.tb.Fatalf("Process %s failed to move to netns: %v", params.Role, err)
	}

	tf.tb.Cleanup(func() {
		syscall.Unmount(p.NSMountPath(), 0)
		os.Remove(p.NSMountPath())
	})

	return p, nil
}

func (tf *TestForker) Resume(config string) (*Process, error) {
	var p Process

	data, err := os.ReadFile(config)
	if err != nil {
		return nil, err
	}

	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)

	if err = dec.Decode(&p); err != nil {
		return nil, err
	}

	return &p, nil
}
