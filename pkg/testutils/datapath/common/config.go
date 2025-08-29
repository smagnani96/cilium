// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package common

type TestConfig struct {
	Pods []struct {
		Name string `yaml:"name" json:"name"`
	} `yaml:"pods" json:"pods"`
	Nodes []struct {
		Name string `yaml:"name" json:"name"`
	} `yaml:"nodes" json:"nodes"`
}
