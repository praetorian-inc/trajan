//go:build ignore
// +build ignore

// Manual check that GetTemplate caches the templates project ID:
// go run pkg/gitlab/manual_test_caching.go <gitlab-token> [base-url]

package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/praetorian-inc/trajan/pkg/gitlab"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("Usage: go run manual_test_caching.go <gitlab-token>")
	}

	token := os.Args[1]
	baseURL := "https://gitlab.com/api/v4"

	if len(os.Args) >= 3 {
		baseURL = os.Args[2]
	}

	fmt.Printf("Testing template caching with GitLab instance: %s\n", baseURL)
	fmt.Println("=" + string(make([]byte, 60)) + "=")

	client := gitlab.NewClient(baseURL, token)
	ctx := context.Background()

	templates := []string{
		"Docker.gitlab-ci.yml",
		"Nodejs.gitlab-ci.yml",
		"Python.gitlab-ci.yml",
	}

	fmt.Println("\nFetching templates (should cache project ID after first call):")

	for i, templateName := range templates {
		start := time.Now()
		content, err := client.GetTemplate(ctx, templateName)
		elapsed := time.Since(start)

		if err != nil {
			log.Fatalf("Failed to fetch template %s: %v", templateName, err)
		}

		fmt.Printf("  %d. %s (fetched in %v, size: %d bytes)\n",
			i+1, templateName, elapsed, len(content))
	}

	fmt.Println("\n✓ Success! All templates fetched.")
	fmt.Println("\nNote: The first template fetch should be slower (fetches project ID),")
	fmt.Println("      subsequent fetches should be faster (uses cached project ID).")

	rl := client.RateLimiter()
	fmt.Printf("\nRate Limiter Stats:\n")
	fmt.Printf("  Limit: %d\n", rl.Limit())
	fmt.Printf("  Remaining: %d\n", rl.Remaining())
}
