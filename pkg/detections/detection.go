package detections

import (
	"context"
	"sort"
	"strings"

	"github.com/praetorian-inc/trajan/pkg/analysis/graph"
)

type Detection interface {
	Name() string
	Platform() string
	Severity() Severity
	Detect(ctx context.Context, g *graph.Graph) ([]Finding, error)
}

type DetectionFactory func() Detection

// Implemented by detections that need live platform API access and produce nothing
// useful from workflow files alone. Not implementing it means local-safe.
type APIRequirer interface {
	RequiresAPI() bool
}

func RequiresAPI(d Detection) bool {
	if r, ok := d.(APIRequirer); ok {
		return r.RequiresAPI()
	}
	return false
}

// Registration order is preserved within each slice.
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

func APIOnlyNames(apiOnly []Detection) string {
	names := make([]string, len(apiOnly))
	for i, d := range apiOnly {
		names[i] = d.Name()
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}
