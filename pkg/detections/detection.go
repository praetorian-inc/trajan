// Package detections provides the detection interface for CI/CD vulnerability detection
package detections

import (
	"context"
	"sort"
	"strings"

	"github.com/praetorian-inc/trajan/pkg/analysis/graph"
)

// Detection detects specific vulnerability types in workflow graphs
type Detection interface {
	Name() string
	Platform() string
	Severity() Severity
	Detect(ctx context.Context, g *graph.Graph) ([]Finding, error)
}

// DetectionFactory creates new detection instances
type DetectionFactory func() Detection

// APIRequirer is an optional interface implemented by detections that
// strictly require platform API access (e.g., live Jenkins instance probes,
// runner enumeration) and produce nothing useful from workflow files alone.
// Detections that do not implement APIRequirer are assumed to be local-safe.
type APIRequirer interface {
	RequiresAPI() bool
}

// RequiresAPI reports whether d strictly requires platform API access.
// Returns false for detections that do not implement APIRequirer.
func RequiresAPI(d Detection) bool {
	if r, ok := d.(APIRequirer); ok {
		return r.RequiresAPI()
	}
	return false
}

// PartitionByAPIRequirement splits detections into local-runnable and
// API-required, preserving registration order in each slice.
func PartitionByAPIRequirement(all []Detection) (localRunnable, apiOnly []Detection) {
	for _, d := range all {
		if RequiresAPI(d) {
			apiOnly = append(apiOnly, d)
		} else {
			localRunnable = append(localRunnable, d)
		}
	}
	return localRunnable, apiOnly
}

// APIOnlyNames returns a sorted comma-separated string of API-only detection names.
// Used for the one-line stderr notice in local mode.
func APIOnlyNames(apiOnly []Detection) string {
	names := make([]string, len(apiOnly))
	for i, d := range apiOnly {
		names[i] = d.Name()
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}
