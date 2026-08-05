package search

import "context"

type SearchResult struct {
	Repositories []string

	// TotalCount counts matching files, not the deduplicated repositories above.
	TotalCount int

	Incomplete bool
}

type SearchProvider interface {
	Search(ctx context.Context, query string) (*SearchResult, error)

	Name() string
}

type SearchOptions struct {
	Organization string

	CustomQuery string

	// MaxResults of 0 means no limit.
	MaxResults int
}

func DefaultSelfHostedQuery(org string) string {
	if org != "" {
		return "self-hosted org:" + org + " language:yaml path:.github/workflows"
	}
	return "self-hosted language:yaml path:.github/workflows"
}
