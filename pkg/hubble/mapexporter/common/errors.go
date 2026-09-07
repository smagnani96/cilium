// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package common

import "errors"

var (
	ErrExporterDisabled        = errors.New("map exporter is disabled")
	ErrExportInProgress        = errors.New("map export is already in progress")
	ErrExportRateLimitExceeded = errors.New("map export rate limit exceeded")
)
