package aiprobe

import (
	"context"
	"time"

	"github.com/praetorian-inc/julius/pkg/probe"
	juliusscanner "github.com/praetorian-inc/julius/pkg/scanner"
	"github.com/praetorian-inc/julius/pkg/types"
	"github.com/praetorian-inc/julius/probes"
)

// ScanConfig controls the Julius probe scan behavior.
type ScanConfig struct {
	Timeout     time.Duration // per-request timeout (default 5s)
	Concurrency int           // max concurrent probes (default 10)
}

// DefaultScanConfig returns sensible defaults.
func DefaultScanConfig() ScanConfig {
	return ScanConfig{
		Timeout:     5 * time.Second,
		Concurrency: 10,
	}
}

// ProbeResult contains the outcome of probing a single endpoint.
type ProbeResult struct {
	Endpoint    DiscoveredEndpoint `json:"endpoint"`
	Reachable   bool               `json:"reachable"`
	Service     string             `json:"service,omitempty"`
	Category    string             `json:"category,omitempty"`
	Specificity int                `json:"specificity,omitempty"`
	Models      []string           `json:"models,omitempty"`
	Error       string             `json:"error,omitempty"`
}

// ScanResults aggregates all probe outcomes.
type ScanResults struct {
	Endpoints []DiscoveredEndpoint `json:"endpoints"`
	Probed    []ProbeResult        `json:"probed"`
	Summary   ScanSummary          `json:"summary"`
}

// ScanSummary provides high-level counts.
type ScanSummary struct {
	EndpointsDiscovered int `json:"endpoints_discovered"`
	EndpointsProbed     int `json:"endpoints_probed"`
	EndpointsReachable  int `json:"endpoints_reachable"`
	ServicesIdentified  int `json:"services_identified"`
}

// ProbeEndpoints runs Julius probes against each discovered endpoint.
func ProbeEndpoints(ctx context.Context, endpoints []DiscoveredEndpoint, config ScanConfig) (*ScanResults, error) {
	if config.Timeout == 0 {
		config.Timeout = 5 * time.Second
	}
	if config.Concurrency == 0 {
		config.Concurrency = 10
	}

	results := &ScanResults{
		Endpoints: endpoints,
	}

	if len(endpoints) == 0 {
		return results, nil
	}

	// Load Julius embedded probes
	loadedProbes, err := probe.LoadProbesFromFS(probes.EmbeddedProbes, ".")
	if err != nil {
		return results, err
	}

	// Create Julius scanner
	s := juliusscanner.NewScanner(config.Timeout, config.Concurrency)

	for _, ep := range endpoints {
		// Respect context cancellation
		select {
		case <-ctx.Done():
			return results, ctx.Err()
		default:
		}

		pr := ProbeResult{Endpoint: ep}

		juliusResults := s.Scan(ep.URL, loadedProbes, false)
		if len(juliusResults) > 0 {
			best := selectBestResult(juliusResults)
			pr.Reachable = true
			pr.Service = best.Service
			pr.Category = best.Category
			pr.Specificity = best.Specificity
			pr.Models = best.Models
			if best.Error != "" {
				pr.Error = best.Error
			}
		}
		// If no results came back and no error, the endpoint was unreachable or
		// didn't match any known service. Reachable stays false.

		results.Probed = append(results.Probed, pr)
	}

	// Compute summary
	results.Summary = computeSummary(results)
	return results, nil
}

// selectBestResult picks the Julius result with the highest specificity.
func selectBestResult(results []types.Result) types.Result {
	best := results[0]
	for i := 1; i < len(results); i++ {
		if results[i].Specificity > best.Specificity {
			best = results[i]
		}
	}
	return best
}

// computeSummary tallies the scan results.
func computeSummary(results *ScanResults) ScanSummary {
	summary := ScanSummary{
		EndpointsDiscovered: len(results.Endpoints),
		EndpointsProbed:     len(results.Probed),
	}
	services := make(map[string]bool)
	for i := range results.Probed {
		pr := &results.Probed[i]
		if pr.Reachable {
			summary.EndpointsReachable++
		}
		if pr.Service != "" {
			services[pr.Service] = true
		}
	}
	summary.ServicesIdentified = len(services)
	return summary
}
