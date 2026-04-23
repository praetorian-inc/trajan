package github

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// === Pull Request Operations ===

// PullRequestInput for creating PRs
type PullRequestInput struct {
	Title string `json:"title"`
	Body  string `json:"body"`
	Head  string `json:"head"` // branch name
	Base  string `json:"base"` // target branch
	Draft bool   `json:"draft,omitempty"`
}

// PullRequest represents a GitHub pull request
type PullRequest struct {
	ID        int    `json:"id"`
	Number    int    `json:"number"`
	State     string `json:"state"`
	Title     string `json:"title"`
	HTMLURL   string `json:"html_url"`
	CreatedAt string `json:"created_at"`
}

// CreatePullRequest creates a new pull request
func (c *Client) CreatePullRequest(ctx context.Context, owner, repo string, input PullRequestInput) (*PullRequest, error) {
	path := fmt.Sprintf("/repos/%s/%s/pulls", owner, repo)

	body, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("marshaling PR input: %w", err)
	}

	resp, err := c.doWrite(ctx, http.MethodPost, path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("creating PR failed (%d): %s", resp.StatusCode, string(respBody))
	}

	var pr PullRequest
	if err := json.NewDecoder(resp.Body).Decode(&pr); err != nil {
		return nil, fmt.Errorf("decoding PR response: %w", err)
	}

	return &pr, nil
}

// ClosePullRequest closes a pull request
func (c *Client) ClosePullRequest(ctx context.Context, owner, repo string, number int) error {
	path := fmt.Sprintf("/repos/%s/%s/pulls/%d", owner, repo, number)

	body := []byte(`{"state": "closed"}`)
	resp, err := c.doWrite(ctx, http.MethodPatch, path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("closing PR failed (%d): %s", resp.StatusCode, string(respBody))
	}

	return nil
}

// === Branch Operations ===

// Reference represents a Git reference
type Reference struct {
	Ref    string `json:"ref"`
	NodeID string `json:"node_id"`
	URL    string `json:"url"`
	Object struct {
		SHA  string `json:"sha"`
		Type string `json:"type"`
		URL  string `json:"url"`
	} `json:"object"`
}

// GetRef gets a Git reference
func (c *Client) GetRef(ctx context.Context, owner, repo, ref string) (*Reference, error) {
	path := fmt.Sprintf("/repos/%s/%s/git/refs/%s", owner, repo, ref)

	var reference Reference
	if err := c.get(ctx, path, &reference); err != nil {
		return nil, fmt.Errorf("getting ref: %w", err)
	}

	return &reference, nil
}

// CreateBranch creates a new branch from a SHA
func (c *Client) CreateBranch(ctx context.Context, owner, repo, branchName, sha string) (*Reference, error) {
	path := fmt.Sprintf("/repos/%s/%s/git/refs", owner, repo)

	input := map[string]string{
		"ref": "refs/heads/" + branchName,
		"sha": sha,
	}

	body, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("marshaling branch input: %w", err)
	}

	resp, err := c.doWrite(ctx, http.MethodPost, path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("creating branch failed (%d): %s", resp.StatusCode, string(respBody))
	}

	var ref Reference
	if err := json.NewDecoder(resp.Body).Decode(&ref); err != nil {
		return nil, fmt.Errorf("decoding branch response: %w", err)
	}

	return &ref, nil
}

// DeleteBranch deletes a branch
func (c *Client) DeleteBranch(ctx context.Context, owner, repo, branchName string) error {
	path := fmt.Sprintf("/repos/%s/%s/git/refs/heads/%s", owner, repo, branchName)

	resp, err := c.doWrite(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("deleting branch failed (%d): %s", resp.StatusCode, string(respBody))
	}

	return nil
}

// === File Operations ===

// FileContentInput for creating/updating files
type FileContentInput struct {
	Message string `json:"message"`
	Content string `json:"content"` // base64 encoded
	Branch  string `json:"branch,omitempty"`
	SHA     string `json:"sha,omitempty"` // Required for updates
}

// FileContent represents a file in a repository
type FileContent struct {
	Type        string `json:"type"`
	Encoding    string `json:"encoding"`
	Size        int    `json:"size"`
	Name        string `json:"name"`
	Path        string `json:"path"`
	Content     string `json:"content"`
	SHA         string `json:"sha"`
	URL         string `json:"url"`
	GitURL      string `json:"git_url"`
	HTMLURL     string `json:"html_url"`
	DownloadURL string `json:"download_url"`
}

// CreateOrUpdateFile creates or updates a file in a repository
func (c *Client) CreateOrUpdateFile(ctx context.Context, owner, repo, path string, input FileContentInput) (*FileContent, error) {
	apiPath := fmt.Sprintf("/repos/%s/%s/contents/%s", owner, repo, path)

	body, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("marshaling file input: %w", err)
	}

	resp, err := c.doWrite(ctx, http.MethodPut, apiPath, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("creating/updating file failed (%d): %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Content FileContent `json:"content"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decoding file response: %w", err)
	}

	return &result.Content, nil
}

// DeleteFile deletes a file from a repository
func (c *Client) DeleteFile(ctx context.Context, owner, repo, path, sha, message, branch string) error {
	apiPath := fmt.Sprintf("/repos/%s/%s/contents/%s", owner, repo, path)

	input := map[string]string{
		"message": message,
		"sha":     sha,
	}
	if branch != "" {
		input["branch"] = branch
	}

	body, err := json.Marshal(input)
	if err != nil {
		return fmt.Errorf("marshaling delete input: %w", err)
	}

	resp, err := c.doWrite(ctx, http.MethodDelete, apiPath, bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("deleting file failed (%d): %s", resp.StatusCode, string(respBody))
	}

	return nil
}

// === Workflow Operations ===

// TriggerWorkflowDispatch triggers a workflow_dispatch event
func (c *Client) TriggerWorkflowDispatch(ctx context.Context, owner, repo, workflowID, ref string, inputs map[string]string) error {
	path := fmt.Sprintf("/repos/%s/%s/actions/workflows/%s/dispatches", owner, repo, workflowID)

	input := map[string]interface{}{
		"ref": ref,
	}
	if len(inputs) > 0 {
		input["inputs"] = inputs
	}

	body, err := json.Marshal(input)
	if err != nil {
		return fmt.Errorf("marshaling dispatch input: %w", err)
	}

	resp, err := c.doWrite(ctx, http.MethodPost, path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("triggering workflow failed (%d): %s", resp.StatusCode, string(respBody))
	}

	return nil
}

// WorkflowRun represents a workflow run
type WorkflowRun struct {
	ID         int64  `json:"id"`
	Name       string `json:"name"`
	HeadBranch string `json:"head_branch"`
	HeadSHA    string `json:"head_sha"`
	Status     string `json:"status"`
	Conclusion string `json:"conclusion"`
	HTMLURL    string `json:"html_url"`
	LogsURL    string `json:"logs_url"`
	CreatedAt  string `json:"created_at"`
}

// GetWorkflowRuns lists recent workflow runs
func (c *Client) GetWorkflowRuns(ctx context.Context, owner, repo string, limit int) ([]WorkflowRun, error) {
	path := fmt.Sprintf("/repos/%s/%s/actions/runs?per_page=%d", owner, repo, limit)

	var result struct {
		WorkflowRuns []WorkflowRun `json:"workflow_runs"`
	}
	if err := c.get(ctx, path, &result); err != nil {
		return nil, fmt.Errorf("listing workflow runs: %w", err)
	}

	return result.WorkflowRuns, nil
}

// GetWorkflowRun gets a single workflow run by ID
func (c *Client) GetWorkflowRun(ctx context.Context, owner, repo string, runID int64) (*WorkflowRun, error) {
	path := fmt.Sprintf("/repos/%s/%s/actions/runs/%d", owner, repo, runID)

	var run WorkflowRun
	if err := c.get(ctx, path, &run); err != nil {
		return nil, fmt.Errorf("getting workflow run: %w", err)
	}

	return &run, nil
}

// DownloadWorkflowRunLogs downloads logs for a workflow run
func (c *Client) DownloadWorkflowRunLogs(ctx context.Context, owner, repo string, runID int64) ([]byte, error) {
	path := fmt.Sprintf("/repos/%s/%s/actions/runs/%d/logs", owner, repo, runID)

	resp, err := c.do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// GitHub returns 302 redirect to actual logs URL
	if resp.StatusCode == http.StatusFound {
		location := resp.Header.Get("Location")
		if location == "" {
			return nil, fmt.Errorf("no redirect location for logs")
		}
		// Follow redirect
		resp, err = http.Get(location)
		if err != nil {
			return nil, fmt.Errorf("following logs redirect: %w", err)
		}
		defer resp.Body.Close()
	}

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("downloading logs failed (%d): %s", resp.StatusCode, string(respBody))
	}

	return io.ReadAll(resp.Body)
}

// === Issue Operations ===

// Issue represents a GitHub issue
type Issue struct {
	ID        int    `json:"id"`
	Number    int    `json:"number"`
	State     string `json:"state"`
	Title     string `json:"title"`
	Body      string `json:"body"`
	HTMLURL   string `json:"html_url"`
	CreatedAt string `json:"created_at"`
}

// CreateIssue creates a new issue
func (c *Client) CreateIssue(ctx context.Context, owner, repo, title, body string) (*Issue, error) {
	path := fmt.Sprintf("/repos/%s/%s/issues", owner, repo)

	input := map[string]string{
		"title": title,
		"body":  body,
	}
	bodyBytes, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("marshaling issue input: %w", err)
	}

	resp, err := c.doWrite(ctx, http.MethodPost, path, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("creating issue failed (%d): %s", resp.StatusCode, string(respBody))
	}

	var issue Issue
	if err := json.NewDecoder(resp.Body).Decode(&issue); err != nil {
		return nil, fmt.Errorf("decoding issue response: %w", err)
	}

	return &issue, nil
}

// CloseIssue closes an issue
func (c *Client) CloseIssue(ctx context.Context, owner, repo string, number int) error {
	path := fmt.Sprintf("/repos/%s/%s/issues/%d", owner, repo, number)

	body := []byte(`{"state": "closed"}`)
	resp, err := c.doWrite(ctx, http.MethodPatch, path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("closing issue failed (%d): %s", resp.StatusCode, string(respBody))
	}

	return nil
}

// === Comment Operations ===

// IssueComment represents a comment on an issue/PR
type IssueComment struct {
	ID        int    `json:"id"`
	Body      string `json:"body"`
	HTMLURL   string `json:"html_url"`
	CreatedAt string `json:"created_at"`
}

// CreateIssueComment creates a comment on an issue or PR
func (c *Client) CreateIssueComment(ctx context.Context, owner, repo string, number int, body string) (*IssueComment, error) {
	path := fmt.Sprintf("/repos/%s/%s/issues/%d/comments", owner, repo, number)

	input := map[string]string{"body": body}
	bodyBytes, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("marshaling comment input: %w", err)
	}

	resp, err := c.doWrite(ctx, http.MethodPost, path, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("creating comment failed (%d): %s", resp.StatusCode, string(respBody))
	}

	var comment IssueComment
	if err := json.NewDecoder(resp.Body).Decode(&comment); err != nil {
		return nil, fmt.Errorf("decoding comment response: %w", err)
	}

	return &comment, nil
}

// DeleteIssueComment deletes a comment
func (c *Client) DeleteIssueComment(ctx context.Context, owner, repo string, commentID int) error {
	path := fmt.Sprintf("/repos/%s/%s/issues/comments/%d", owner, repo, commentID)

	resp, err := c.doWrite(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("deleting comment failed (%d): %s", resp.StatusCode, string(respBody))
	}

	return nil
}

// === Repository Operations (for C2) ===

// CreateRepositoryInput for creating repositories
type CreateRepositoryInput struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Private     bool   `json:"private"`
	AutoInit    bool   `json:"auto_init,omitempty"`
}

// CreateRepository creates a new repository
func (c *Client) CreateRepository(ctx context.Context, input CreateRepositoryInput) (*Repository, error) {
	path := "/user/repos"

	body, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("marshaling repo input: %w", err)
	}

	resp, err := c.doWrite(ctx, http.MethodPost, path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("creating repository failed (%d): %s", resp.StatusCode, string(respBody))
	}

	var repo Repository
	if err := json.NewDecoder(resp.Body).Decode(&repo); err != nil {
		return nil, fmt.Errorf("decoding repository response: %w", err)
	}

	return &repo, nil
}

// DeleteRepository deletes a repository
func (c *Client) DeleteRepository(ctx context.Context, owner, repo string) error {
	path := fmt.Sprintf("/repos/%s/%s", owner, repo)

	resp, err := c.doWrite(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("deleting repository failed (%d): %s", resp.StatusCode, string(respBody))
	}

	return nil
}

// === Collaborator Operations ===

// CollaboratorPermission defines permission levels for collaborators
type CollaboratorPermission string

const (
	PermissionPull     CollaboratorPermission = "pull"
	PermissionTriage   CollaboratorPermission = "triage"
	PermissionPush     CollaboratorPermission = "push"
	PermissionMaintain CollaboratorPermission = "maintain"
	PermissionAdmin    CollaboratorPermission = "admin"
)

// InviteCollaborator invites a user as a repository collaborator
// API: PUT /repos/{owner}/{repo}/collaborators/{username}
func (c *Client) InviteCollaborator(ctx context.Context, owner, repo, username string, permission CollaboratorPermission) error {
	path := fmt.Sprintf("/repos/%s/%s/collaborators/%s", owner, repo, username)

	input := map[string]string{
		"permission": string(permission),
	}

	body, err := json.Marshal(input)
	if err != nil {
		return fmt.Errorf("marshaling input: %w", err)
	}

	resp, err := c.doWrite(ctx, http.MethodPut, path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusNoContent {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("inviting collaborator failed (%d): %s", resp.StatusCode, string(respBody))
	}

	return nil
}

// RemoveCollaborator removes a user from repository collaborators
// API: DELETE /repos/{owner}/{repo}/collaborators/{username}
func (c *Client) RemoveCollaborator(ctx context.Context, owner, repo, username string) error {
	path := fmt.Sprintf("/repos/%s/%s/collaborators/%s", owner, repo, username)

	resp, err := c.doWrite(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("removing collaborator failed (%d): %s", resp.StatusCode, string(respBody))
	}

	return nil
}

// === Write Helper ===

// doWrite performs a write HTTP request with rate limiting
func (c *Client) doWrite(ctx context.Context, method, path string, body io.Reader) (*http.Response, error) {
	// Acquire concurrency slot
	if err := c.semaphore.Acquire(ctx, 1); err != nil {
		return nil, fmt.Errorf("acquiring concurrency slot: %w", err)
	}
	defer c.semaphore.Release(1)

	// Wait if rate limited
	if err := c.rateLimiter.Wait(ctx); err != nil {
		return nil, fmt.Errorf("rate limit wait: %w", err)
	}

	url := c.baseURL + path
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}

	// Update rate limiter from response
	c.rateLimiter.Update(resp.Header)

	if ct := resp.Header.Get("Content-Type"); strings.Contains(ct, "text/html") {
		resp.Body.Close()
		return nil, fmt.Errorf("server returned HTML instead of JSON (Content-Type: %s) — GitHub Enterprise Server may be in maintenance/replication mode, or the --url may be incorrect", ct)
	}

	return resp, nil
}
