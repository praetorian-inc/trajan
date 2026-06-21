package github

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/praetorian-inc/trajan/internal/cmdutil"

	"github.com/praetorian-inc/trajan/pkg/platforms/shared/proxy"
	"github.com/praetorian-inc/trajan/pkg/search"
)

var searchCmd = &cobra.Command{
	Use:   "search",
	Short: "Search for repositories with self-hosted runners",
	Long: `Trajan - GitHub - Search

Search for repositories potentially using self-hosted runners.

This command searches GitHub code search or SourceGraph for workflow files
that reference self-hosted runners, helping identify targets with
non-ephemeral CI/CD infrastructure.

Supported Providers:
  github       Search via GitHub code search API (requires token)
  sourcegraph  Search via SourceGraph public API (no auth required)`,
	RunE: runSearch,
}

var (
	searchProvider string
	searchOrg      string
	searchQuery    string
	searchOutput   string
)

func init() {
	searchCmd.Flags().SortFlags = false
	searchCmd.Flags().StringVarP(&searchProvider, "provider", "p", "github", "Search provider (github, sourcegraph)")
	searchCmd.Flags().StringVar(&searchOrg, "org", "", "Organization to search within")
	searchCmd.Flags().StringVarP(&searchQuery, "query", "q", "", "Custom search query")
	searchCmd.Flags().StringVar(&searchOutput, "output-file", "", "Output file for results")
}

func runSearch(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	httpProxy := cmdutil.GetHTTPProxy(cmd)
	socksProxy := cmdutil.GetSOCKSProxy(cmd)

	var provider search.SearchProvider
	var query string

	switch strings.ToLower(searchProvider) {
	case "github":
		t := getToken(cmd)
		if t == "" {
			return fmt.Errorf("github token required for GitHub search")
		}

		// Create HTTP client for search with proxy support if provided
		var httpClient *http.Client
		proxyTransport, err := proxy.NewTransport(proxy.Config{
			HTTPProxy:  httpProxy,
			SOCKSProxy: socksProxy,
		})
		if err != nil {
			return fmt.Errorf("creating proxy transport: %w", err)
		}
		if proxyTransport != nil {
			httpClient = &http.Client{
				Transport: proxyTransport,
				Timeout:   60 * time.Second,
			}
		} else {
			httpClient = &http.Client{
				Timeout: 60 * time.Second,
			}
		}

		provider = search.NewGitHubSearchProvider(httpClient, t)

		if searchQuery != "" {
			query = searchQuery
		} else {
			query = search.DefaultSelfHostedQuery(searchOrg)
		}

	case "sourcegraph":
		provider = search.NewSourceGraphSearchProvider(httpProxy)

		if searchQuery != "" {
			query = searchQuery
		} else {
			query = search.DefaultSourceGraphQuery(searchOrg)
		}

	default:
		return fmt.Errorf("unknown search provider: %s", searchProvider)
	}

	fmt.Printf("Searching with %s...\n", provider.Name())
	fmt.Printf("Query: %s\n\n", query)

	result, err := provider.Search(ctx, query)
	if err != nil {
		return fmt.Errorf("search failed: %w", err)
	}

	fmt.Printf("Found %d repositories\n\n", len(result.Repositories))

	if result.Incomplete {
		fmt.Println("Warning: Results may be incomplete due to API timeout")
	}

	// Output results
	if searchOutput != "" {
		f, err := os.Create(searchOutput)
		if err != nil {
			return fmt.Errorf("creating output file: %w", err)
		}
		defer func() { _ = f.Close() }()

		for _, repo := range result.Repositories {
			_, _ = fmt.Fprintln(f, repo)
		}
		fmt.Printf("Results written to %s\n", searchOutput)
	} else {
		for _, repo := range result.Repositories {
			fmt.Println(repo)
		}
	}

	return nil
}
