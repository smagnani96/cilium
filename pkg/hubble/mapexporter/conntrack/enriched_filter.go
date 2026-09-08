// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package conntrack

import (
	"fmt"
	"slices"
	"strings"

	observerpb "github.com/cilium/cilium/api/v1/observer"
	"github.com/cilium/cilium/pkg/hubble/k8s"
)

// enrichedFilter matches ConntrackEntry values against a
// *observerpb.ConntrackEnrichedFilter. Unlike entryFilter, every field it
// inspects (identity, pod name, service name) is only populated by
// enrichment, so it must only be evaluated on entries built with
// enrich=true. A nil enrichedFilter matches every entry.
type enrichedFilter struct {
	sourceIdentities, destIdentities []uint32
	sourcePods, destPods             []namespacedNameFilter
	services                         []namespacedNameFilter
}

// namespacedNameFilter matches a namespace/name pair the same way
// `hubble observe`'s pod/service filters do: namespace, if set, must match
// exactly, and name, if set, is matched as a prefix.
type namespacedNameFilter struct {
	namespace, namePrefix string
}

func newNamespacedNameFilters(names []string) ([]namespacedNameFilter, error) {
	filters := make([]namespacedNameFilter, 0, len(names))
	for _, name := range names {
		if name == "" {
			return nil, fmt.Errorf("name must not be empty")
		}
		ns, prefix := k8s.ParseNamespaceName(name)
		filters = append(filters, namespacedNameFilter{namespace: ns, namePrefix: prefix})
	}
	return filters, nil
}

func matchNamespacedName(ns, name string, filters []namespacedNameFilter) bool {
	if len(filters) == 0 {
		return true
	}
	if ns == "" && name == "" {
		return false
	}
	return slices.ContainsFunc(filters, func(f namespacedNameFilter) bool {
		return (f.namePrefix == "" || strings.HasPrefix(name, f.namePrefix)) && (f.namespace == "" || f.namespace == ns)
	})
}

// newEnrichedFilter validates f and builds a matcher for it. It returns a
// nil enrichedFilter, without error, if f is nil or every one of its fields
// is unset.
func newEnrichedFilter(f *observerpb.ConntrackEnrichedFilter) (*enrichedFilter, error) {
	if f == nil {
		return nil, nil
	}

	ef := &enrichedFilter{
		sourceIdentities: f.GetSourceIdentity(),
		destIdentities:   f.GetDestinationIdentity(),
	}

	var err error
	if ef.sourcePods, err = newNamespacedNameFilters(f.GetSourcePod()); err != nil {
		return nil, fmt.Errorf("invalid source_pod filter: %w", err)
	}
	if ef.destPods, err = newNamespacedNameFilters(f.GetDestinationPod()); err != nil {
		return nil, fmt.Errorf("invalid destination_pod filter: %w", err)
	}
	if ef.services, err = newNamespacedNameFilters(f.GetService()); err != nil {
		return nil, fmt.Errorf("invalid service filter: %w", err)
	}

	if ef.isEmpty() {
		return nil, nil
	}
	return ef, nil
}

func (ef *enrichedFilter) isEmpty() bool {
	return len(ef.sourceIdentities) == 0 && len(ef.destIdentities) == 0 &&
		len(ef.sourcePods) == 0 && len(ef.destPods) == 0 && len(ef.services) == 0
}

// match reports whether e matches every field set on ef. A nil ef matches
// every entry.
func (ef *enrichedFilter) match(e *observerpb.ConntrackEntry) bool {
	if ef == nil {
		return true
	}
	if len(ef.sourceIdentities) > 0 && !slices.Contains(ef.sourceIdentities, e.GetSource().GetIdentity()) {
		return false
	}
	if len(ef.destIdentities) > 0 && !slices.Contains(ef.destIdentities, e.GetDestination().GetIdentity()) {
		return false
	}
	if !matchNamespacedName(e.GetSource().GetNamespace(), e.GetSource().GetPodName(), ef.sourcePods) {
		return false
	}
	if !matchNamespacedName(e.GetDestination().GetNamespace(), e.GetDestination().GetPodName(), ef.destPods) {
		return false
	}
	if !matchNamespacedName(e.GetService().GetNamespace(), e.GetService().GetName(), ef.services) {
		return false
	}
	return true
}
