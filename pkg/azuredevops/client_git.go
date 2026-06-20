package azuredevops

import (
	"context"
	"fmt"
	"net/url"
)

// ListGitRefs lists git refs (branches/tags) in a repository
// API: GET {org}/{project}/_apis/git/repositories/{repo}/refs?api-version=7.1-preview.1
func (c *Client) ListGitRefs(ctx context.Context, projectNameOrID, repoNameOrID string) ([]GitRef, error) {
	encodedProject := url.PathEscape(projectNameOrID)
	encodedRepo := url.PathEscape(repoNameOrID)
	path := fmt.Sprintf("/%s/_apis/git/repositories/%s/refs?api-version=%s", encodedProject, encodedRepo, APIVersion)

	var result GitRefList
	if err := c.getJSON(ctx, path, &result); err != nil {
		return nil, fmt.Errorf("listing git refs: %w", err)
	}
	return result.Value, nil
}

// ListGitBranches lists git branches (filter=heads) in a repository
// API: GET {org}/{project}/_apis/git/repositories/{repo}/refs?filter=heads/&api-version=7.1-preview.1
func (c *Client) ListGitBranches(ctx context.Context, projectNameOrID, repoNameOrID string) ([]GitRef, error) {
	encodedProject := url.PathEscape(projectNameOrID)
	encodedRepo := url.PathEscape(repoNameOrID)
	path := fmt.Sprintf("/%s/_apis/git/repositories/%s/refs?filter=heads/&api-version=%s", encodedProject, encodedRepo, APIVersion)

	var result GitRefList
	if err := c.getJSON(ctx, path, &result); err != nil {
		return nil, fmt.Errorf("listing git branches: %w", err)
	}
	return result.Value, nil
}

// CreateBranch creates a new branch in a repository
// API: POST {org}/{project}/_apis/git/repositories/{repo}/refs?api-version=7.1-preview.1
func (c *Client) CreateBranch(ctx context.Context, projectNameOrID, repoNameOrID, branchName, sourceCommitID string) error {
	encodedProject := url.PathEscape(projectNameOrID)
	encodedRepo := url.PathEscape(repoNameOrID)
	path := fmt.Sprintf("/%s/_apis/git/repositories/%s/refs?api-version=%s", encodedProject, encodedRepo, APIVersion)

	updates := []GitRefUpdate{{
		Name:        "refs/heads/" + branchName,
		OldObjectID: "0000000000000000000000000000000000000000",
		NewObjectID: sourceCommitID,
	}}

	var result GitRefList
	if err := c.postJSON(ctx, path, updates, &result); err != nil {
		return fmt.Errorf("creating branch: %w", err)
	}
	if len(result.Value) == 0 {
		return fmt.Errorf("creating branch %q: API returned empty response", branchName)
	}
	if !result.Value[0].Success {
		return fmt.Errorf("creating branch %q: %s", branchName, result.Value[0].UpdateStatus)
	}
	return nil
}

// DeleteBranch deletes a branch from a repository
// API: POST {org}/{project}/_apis/git/repositories/{repo}/refs?api-version=7.1-preview.1
func (c *Client) DeleteBranch(ctx context.Context, projectNameOrID, repoNameOrID, branchName, objectID string) error {
	encodedProject := url.PathEscape(projectNameOrID)
	encodedRepo := url.PathEscape(repoNameOrID)
	path := fmt.Sprintf("/%s/_apis/git/repositories/%s/refs?api-version=%s", encodedProject, encodedRepo, APIVersion)

	updates := []GitRefUpdate{{
		Name:        "refs/heads/" + branchName,
		OldObjectID: objectID,
		NewObjectID: "0000000000000000000000000000000000000000",
	}}

	var result GitRefList
	if err := c.postJSON(ctx, path, updates, &result); err != nil {
		return fmt.Errorf("deleting branch: %w", err)
	}
	if len(result.Value) == 0 {
		return fmt.Errorf("deleting branch %q: API returned empty response", branchName)
	}
	if !result.Value[0].Success {
		return fmt.Errorf("deleting branch %q: %s", branchName, result.Value[0].UpdateStatus)
	}
	return nil
}

// PushFile pushes a file to a repository
// API: POST {org}/{project}/_apis/git/repositories/{repo}/pushes?api-version=7.1-preview.1
func (c *Client) PushFile(ctx context.Context, projectNameOrID, repoNameOrID, branchName, filePath, content, commitMessage, oldObjectID string) error {
	encodedProject := url.PathEscape(projectNameOrID)
	encodedRepo := url.PathEscape(repoNameOrID)
	apiPath := fmt.Sprintf("/%s/_apis/git/repositories/%s/pushes?api-version=%s", encodedProject, encodedRepo, APIVersion)

	push := GitPush{
		RefUpdates: []GitRefUpdate{{
			Name:        "refs/heads/" + branchName,
			OldObjectID: oldObjectID,
		}},
		Commits: []GitCommit{{
			Comment: commitMessage,
			Changes: []GitChange{{
				ChangeType: "add",
				Item: struct {
					Path string `json:"path"`
				}{Path: "/" + filePath},
				NewContent: &GitItemContent{
					Content:     content,
					ContentType: "rawtext",
				},
			}},
		}},
	}

	var result map[string]interface{}
	if err := c.postJSON(ctx, apiPath, push, &result); err != nil {
		return fmt.Errorf("pushing file: %w", err)
	}
	return nil
}

// ListRepoItems lists files/folders in a repository
// API: GET {org}/{project}/_apis/git/repositories/{repo}/items?recursionLevel=Full&api-version=7.1-preview.1
func (c *Client) ListRepoItems(ctx context.Context, projectNameOrID, repoNameOrID string) ([]RepoItem, error) {
	encodedProject := url.PathEscape(projectNameOrID)
	encodedRepo := url.PathEscape(repoNameOrID)
	path := fmt.Sprintf("/%s/_apis/git/repositories/%s/items?recursionLevel=Full&api-version=%s", encodedProject, encodedRepo, APIVersion)

	var result RepoItemList
	if err := c.getJSON(ctx, path, &result); err != nil {
		return nil, fmt.Errorf("listing repo items: %w", err)
	}
	return result.Value, nil
}

// CreatePullRequest creates a new pull request
// API: POST {org}/{project}/_apis/git/repositories/{repo}/pullrequests?api-version=7.1
func (c *Client) CreatePullRequest(ctx context.Context, projectNameOrID, repoNameOrID string, req PullRequestCreateRequest) (*PullRequest, error) {
	encodedProject := url.PathEscape(projectNameOrID)
	encodedRepo := url.PathEscape(repoNameOrID)
	path := fmt.Sprintf("/%s/_apis/git/repositories/%s/pullrequests?api-version=%s", encodedProject, encodedRepo, APIVersion)

	var result PullRequest
	if err := c.postJSON(ctx, path, req, &result); err != nil {
		return nil, fmt.Errorf("creating pull request: %w", err)
	}
	return &result, nil
}

// AbandonPullRequest sets a pull request status to abandoned
// API: PATCH {org}/{project}/_apis/git/repositories/{repo}/pullrequests/{pullRequestId}?api-version=7.1
func (c *Client) AbandonPullRequest(ctx context.Context, projectNameOrID, repoNameOrID string, pullRequestID int) error {
	encodedProject := url.PathEscape(projectNameOrID)
	encodedRepo := url.PathEscape(repoNameOrID)
	path := fmt.Sprintf("/%s/_apis/git/repositories/%s/pullrequests/%d?api-version=%s", encodedProject, encodedRepo, pullRequestID, APIVersion)

	body := map[string]string{"status": "abandoned"}
	var result map[string]interface{}
	if err := c.patchJSON(ctx, path, body, &result); err != nil {
		return fmt.Errorf("abandoning pull request: %w", err)
	}
	return nil
}
