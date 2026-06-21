package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/praetorian-inc/trajan/pkg/search"
)

var searchCmd = &cobra.Command{
	Use:   "search",
	Short: "Search for repositories with self-hosted runners",
	Long: `Trajan - Search

Search for repositories potentially using self-hosted runners.

This command searches SourceGraph for workflow files that reference
self-hosted runners, helping identify targets with non-ephemeral CI/CD
infrastructure.

For GitHub search, use: trajan github search

Supported Providers:
  sourcegraph  Search via SourceGraph public API (no auth required)

Authentication:
  SourceGraph provider works without authentication for public repositories.
  For GitHub search, use: trajan github search`,
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
	searchCmd.Flags().StringVarP(&searchProvider, "provider", "p", "sourcegraph", "Search provider (sourcegraph; for github use: trajan github search)")
	searchCmd.Flags().StringVar(&searchOrg, "org", "", "Organization to search within")
	searchCmd.Flags().StringVarP(&searchQuery, "query", "q", "", "Custom search query")
	searchCmd.Flags().StringVar(&searchOutput, "output-file", "", "Output file for results")
}

func runSearch(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	var provider search.SearchProvider
	var query string

	switch strings.ToLower(searchProvider) {
	case "github":
		return fmt.Errorf("GitHub search has moved to: trajan github search")

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
