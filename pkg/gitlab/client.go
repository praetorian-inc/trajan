// pkg/platforms/gitlab/client.go
package gitlab

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/semaphore"
)

const (
	DefaultBaseURL        = "https://gitlab.com/api/v4"
	DefaultTimeout        = 30 * time.Second
	MaxConcurrentRequests = 100 // GitLab rate limit: 300-2000 req/min depending on tier
)

// Client is a GitLab REST API v4 client with rate limiting
type Client struct {
	httpClient  *http.Client
	baseURL     string
	token       string
	rateLimiter *RateLimiter
	semaphore   *semaphore.Weighted

	// Template project caching (reduces redundant GetProject calls)
	templatesProjectID   *int
	templatesProjectLock sync.RWMutex
}

// String implements fmt.Stringer to prevent token leakage in logs
func (c *Client) String() string {
	if c == nil {
		return "Client{nil}"
	}

	return fmt.Sprintf("Client{baseURL: %q, token: [REDACTED], rateLimiter: %+v}",
		c.baseURL,
		c.rateLimiter,
	)
}

// GoString implements fmt.GoStringer to prevent token leakage with %#v format
func (c *Client) GoString() string {
	if c == nil {
		return "(*Client)(nil)"
	}

	return fmt.Sprintf("&Client{baseURL: %q, token: [REDACTED], rateLimiter: %#v}",
		c.baseURL,
		c.rateLimiter,
	)
}

// ClientOption configures a Client
type ClientOption func(*Client)

// WithTimeout sets the HTTP client timeout
func WithTimeout(timeout time.Duration) ClientOption {
	return func(c *Client) {
		c.httpClient.Timeout = timeout
	}
}

// WithConcurrency sets the maximum concurrent requests
func WithConcurrency(max int64) ClientOption {
	return func(c *Client) {
		if max > 0 {
			c.semaphore = semaphore.NewWeighted(max)
		}
	}
}

// WithHTTPTransport sets a custom HTTP transport on the underlying client.
func WithHTTPTransport(transport http.RoundTripper) ClientOption {
	return func(c *Client) {
		c.httpClient.Transport = transport
	}
}

// NewClient creates a new GitLab REST API v4 client
// Authentication: Uses PRIVATE-TOKEN header
func NewClient(baseURL, token string, opts ...ClientOption) *Client {
	if baseURL == "" {
		baseURL = DefaultBaseURL
	} else {
		// Auto-append /api/v4 if not present for self-hosted instances
		if !strings.HasSuffix(baseURL, "/api/v4") {
			baseURL = strings.TrimRight(baseURL, "/") + "/api/v4"
		}
	}

	c := &Client{
		httpClient: &http.Client{
			Timeout: DefaultTimeout,
		},
		baseURL:     baseURL,
		token:       token,
		rateLimiter: NewRateLimiter(),
		semaphore:   semaphore.NewWeighted(MaxConcurrentRequests),
	}

	// Apply options
	for _, opt := range opts {
		opt(c)
	}

	return c
}

// GetProject retrieves a single project
func (c *Client) GetProject(ctx context.Context, projectPath string) (*Project, error) {
	// URL-encode the project path (e.g., "owner/repo" -> "owner%2Frepo")
	encodedPath := url.PathEscape(projectPath)
	path := fmt.Sprintf("/projects/%s", encodedPath)

	var project Project
	if err := c.getJSON(ctx, path, &project); err != nil {
		return nil, fmt.Errorf("getting project: %w", err)
	}

	return &project, nil
}

// ListGroupProjects lists all projects in a group
func (c *Client) ListGroupProjects(ctx context.Context, groupName string) ([]Project, error) {
	encodedGroup := url.PathEscape(groupName)
	path := fmt.Sprintf("/groups/%s/projects", encodedGroup)

	var projects []Project
	if err := c.getPaginatedJSON(ctx, path, 20, &projects); err != nil {
		return nil, fmt.Errorf("listing group projects: %w", err)
	}

	return projects, nil
}

// ListUserProjects lists all projects for a user
func (c *Client) ListUserProjects(ctx context.Context, username string) ([]Project, error) {
	path := fmt.Sprintf("/users/%s/projects", url.PathEscape(username))

	var projects []Project
	if err := c.getPaginatedJSON(ctx, path, 20, &projects); err != nil {
		return nil, fmt.Errorf("listing user projects: %w", err)
	}

	return projects, nil
}

// GetWorkflowFile retrieves a .gitlab-ci.yml file
// ref should be a branch name, tag, or commit SHA
func (c *Client) GetWorkflowFile(ctx context.Context, projectID int, filePath, ref string) ([]byte, error) {
	// GitLab API: GET /api/v4/projects/:id/repository/files/:file_path?ref=:ref
	encodedPath := url.PathEscape(filePath)
	apiPath := fmt.Sprintf("/projects/%d/repository/files/%s?ref=%s", projectID, encodedPath, url.QueryEscape(ref))

	var fileResp FileResponse
	if err := c.getJSON(ctx, apiPath, &fileResp); err != nil {
		return nil, fmt.Errorf("getting workflow file: %w", err)
	}

	// Decode base64 content if needed
	if fileResp.Encoding == "base64" {
		return decodeBase64(fileResp.Content)
	}

	return []byte(fileResp.Content), nil
}

// GetTemplate retrieves a GitLab CI template
func (c *Client) GetTemplate(ctx context.Context, templateName string) ([]byte, error) {
	// GitLab templates are in gitlab-org/gitlab repo
	// Path: lib/gitlab/ci/templates/{templateName}
	const (
		templatesProject = "gitlab-org/gitlab"
		templatesPath    = "lib/gitlab/ci/templates"
		templatesBranch  = "master"
	)

	filePath := fmt.Sprintf("%s/%s", templatesPath, templateName)

	// Lazy-load project ID with double-checked locking
	c.templatesProjectLock.RLock()
	projectID := c.templatesProjectID
	c.templatesProjectLock.RUnlock()

	if projectID == nil {
		c.templatesProjectLock.Lock()
		if c.templatesProjectID == nil { // Double-check
			project, err := c.GetProject(ctx, templatesProject)
			if err != nil {
				c.templatesProjectLock.Unlock()
				return nil, fmt.Errorf("getting templates project: %w", err)
			}
			c.templatesProjectID = &project.ID
		}
		projectID = c.templatesProjectID
		c.templatesProjectLock.Unlock()
	}

	return c.GetWorkflowFile(ctx, *projectID, filePath, templatesBranch)
}

// decodeBase64 decodes base64 content
// GitLab returns base64-encoded content for binary files
func decodeBase64(s string) ([]byte, error) {
	// GitLab returns content with newlines
	s = strings.ReplaceAll(s, "\n", "")
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("decoding base64: %w", err)
	}
	return decoded, nil
}

// GetUser retrieves the current authenticated user
// GET /api/v4/user
func (c *Client) GetUser(ctx context.Context) (*User, error) {
	var user User
	if err := c.getJSON(ctx, "/user", &user); err != nil {
		return nil, fmt.Errorf("getting user: %w", err)
	}
	return &user, nil
}

// GetPersonalAccessToken retrieves info about the current token
// GET /api/v4/personal_access_tokens/self
// Note: May fail for project/group tokens or older GitLab versions
func (c *Client) GetPersonalAccessToken(ctx context.Context) (*PersonalAccessToken, error) {
	var pat PersonalAccessToken
	if err := c.getJSON(ctx, "/personal_access_tokens/self", &pat); err != nil {
		return nil, fmt.Errorf("getting personal access token: %w", err)
	}
	return &pat, nil
}

// ListGroups lists groups accessible to the token
// GET /api/v4/groups
func (c *Client) ListGroups(ctx context.Context) ([]Group, error) {
	var groups []Group
	if err := c.getPaginatedJSON(ctx, "/groups", 20, &groups); err != nil {
		return nil, fmt.Errorf("listing groups: %w", err)
	}
	return groups, nil
}

// ListAllProjects lists all projects accessible to the token
// GET /api/v4/projects
func (c *Client) ListAllProjects(ctx context.Context) ([]Project, error) {
	var projects []Project
	if err := c.getPaginatedJSON(ctx, "/projects", 20, &projects); err != nil {
		return nil, fmt.Errorf("listing projects: %w", err)
	}
	return projects, nil
}

// ListMemberProjects lists projects where user is a member with permissions
// GET /api/v4/projects?membership=true
func (c *Client) ListMemberProjects(ctx context.Context) ([]Project, error) {
	var projects []Project
	if err := c.getPaginatedJSON(ctx, "/projects?membership=true", 20, &projects); err != nil {
		return nil, fmt.Errorf("listing member projects: %w", err)
	}
	return projects, nil
}

// ListProjectMembers lists members of a project with access levels
// GET /api/v4/projects/:id/members
func (c *Client) ListProjectMembers(ctx context.Context, projectID int) ([]Member, error) {
	path := fmt.Sprintf("/projects/%d/members", projectID)
	var members []Member
	if err := c.getJSON(ctx, path, &members); err != nil {
		return nil, fmt.Errorf("listing project members: %w", err)
	}
	return members, nil
}

// ListProjectPipelines lists all pipelines for a project (no filtering)
// Deprecated: Use ListPipelines with empty ref instead for new code
// GET /api/v4/projects/:id/pipelines
func (c *Client) ListProjectPipelines(ctx context.Context, projectID int) ([]Pipeline, error) {
	return c.ListPipelines(ctx, projectID, "")
}

// ListProjectVariables lists CI/CD variables for a project
// GET /api/v4/projects/:id/variables
func (c *Client) ListProjectVariables(ctx context.Context, projectID int) ([]Variable, error) {
	path := fmt.Sprintf("/projects/%d/variables", projectID)
	var variables []Variable
	if err := c.getPaginatedJSON(ctx, path, 20, &variables); err != nil {
		return nil, fmt.Errorf("listing project variables: %w", err)
	}
	return variables, nil
}

// ListGroupMembers lists members of a group with access levels
// GET /api/v4/groups/:id/members
func (c *Client) ListGroupMembers(ctx context.Context, groupID int) ([]Member, error) {
	path := fmt.Sprintf("/groups/%d/members", groupID)
	var members []Member
	if err := c.getJSON(ctx, path, &members); err != nil {
		return nil, fmt.Errorf("listing group members: %w", err)
	}
	return members, nil
}

// GetProjectAccessLevel gets the current user's access level for a project
// Uses /api/v4/projects/:id/members/:user_id endpoint
func (c *Client) GetProjectAccessLevel(ctx context.Context, projectID, userID int) (int, error) {
	path := fmt.Sprintf("/projects/%d/members/%d", projectID, userID)
	var member Member
	if err := c.getJSON(ctx, path, &member); err != nil {
		return 0, fmt.Errorf("getting project access level: %w", err)
	}
	return member.AccessLevel, nil
}

// GetGroupAccessLevel gets the current user's access level for a group
// Uses /api/v4/groups/:id/members/:user_id endpoint
func (c *Client) GetGroupAccessLevel(ctx context.Context, groupID, userID int) (int, error) {
	path := fmt.Sprintf("/groups/%d/members/%d", groupID, userID)
	var member Member
	if err := c.getJSON(ctx, path, &member); err != nil {
		return 0, fmt.Errorf("getting group access level: %w", err)
	}
	return member.AccessLevel, nil
}

// RateLimiter returns the underlying rate limiter
func (c *Client) RateLimiter() *RateLimiter {
	return c.rateLimiter
}

// GetGroup gets a group by its path
// GET /api/v4/groups/:id
func (c *Client) GetGroup(ctx context.Context, groupPath string) (*Group, error) {
	encodedPath := url.PathEscape(groupPath)
	path := fmt.Sprintf("/groups/%s", encodedPath)

	var group Group
	if err := c.getJSON(ctx, path, &group); err != nil {
		return nil, fmt.Errorf("getting group: %w", err)
	}
	return &group, nil
}

// ListSubgroups lists subgroups of a group
// GET /api/v4/groups/:id/subgroups
func (c *Client) ListSubgroups(ctx context.Context, groupID int) ([]Group, error) {
	path := fmt.Sprintf("/groups/%d/subgroups", groupID)
	var groups []Group
	if err := c.getPaginatedJSON(ctx, path, 20, &groups); err != nil {
		return nil, fmt.Errorf("listing subgroups: %w", err)
	}
	return groups, nil
}

// ListSharedGroups lists groups shared with a group
// GET /api/v4/groups/:id/groups/shared
func (c *Client) ListSharedGroups(ctx context.Context, groupID int) ([]SharedGroup, error) {
	path := fmt.Sprintf("/groups/%d/groups/shared", groupID)
	var groups []SharedGroup
	if err := c.getPaginatedJSON(ctx, path, 20, &groups); err != nil {
		return nil, fmt.Errorf("listing shared groups: %w", err)
	}
	return groups, nil
}

// ListGroupVariables lists CI/CD variables for a group
// GET /api/v4/groups/:id/variables
func (c *Client) ListGroupVariables(ctx context.Context, groupID int) ([]Variable, error) {
	path := fmt.Sprintf("/groups/%d/variables", groupID)
	var variables []Variable
	if err := c.getPaginatedJSON(ctx, path, 20, &variables); err != nil {
		// 403 Forbidden is expected for non-maintainer users - return empty list
		// Other errors (network, 500s, JSON decode) should be propagated
		if isPermissionError(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("listing group variables: %w", err)
	}
	return variables, nil
}

// ListInstanceVariables lists instance-level CI/CD variables
// GET /api/v4/admin/ci/variables
// Note: Requires admin access
func (c *Client) ListInstanceVariables(ctx context.Context) ([]Variable, error) {
	var variables []Variable
	if err := c.getJSON(ctx, "/admin/ci/variables", &variables); err != nil {
		// 403 Forbidden is expected for non-admin users - return empty list
		// Other errors (network, 500s, JSON decode) should be propagated
		if isPermissionError(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("listing instance variables: %w", err)
	}
	return variables, nil
}

// isPermissionError checks if an error is a 403 Forbidden permission error.
func isPermissionError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return strings.Contains(errStr, "403") || strings.Contains(errStr, "Forbidden")
}

// ListProtectedBranches lists protected branches for a project
// GET /api/v4/projects/:id/protected_branches
func (c *Client) ListProtectedBranches(ctx context.Context, projectID int) ([]BranchProtection, error) {
	path := fmt.Sprintf("/projects/%d/protected_branches", projectID)
	var protections []BranchProtection
	if err := c.getPaginatedJSON(ctx, path, 20, &protections); err != nil {
		return nil, fmt.Errorf("listing protected branches: %w", err)
	}
	return protections, nil
}

// ListProjectRunners lists runners for a project
// GET /api/v4/projects/:id/runners
func (c *Client) ListProjectRunners(ctx context.Context, projectID int) ([]RunnerInfo, error) {
	path := fmt.Sprintf("/projects/%d/runners", projectID)
	var runners []RunnerInfo
	if err := c.getPaginatedJSON(ctx, path, 20, &runners); err != nil {
		return nil, fmt.Errorf("listing project runners: %w", err)
	}
	return runners, nil
}

// ListGroupRunners lists runners for a group
// GET /api/v4/groups/:id/runners
func (c *Client) ListGroupRunners(ctx context.Context, groupID int) ([]RunnerInfo, error) {
	path := fmt.Sprintf("/groups/%d/runners", groupID)
	var runners []RunnerInfo
	if err := c.getPaginatedJSON(ctx, path, 20, &runners); err != nil {
		return nil, fmt.Errorf("listing group runners: %w", err)
	}
	return runners, nil
}

// ListInstanceRunners lists all instance-level runners
// GET /api/v4/runners/all
// Note: Requires admin access
func (c *Client) ListInstanceRunners(ctx context.Context) ([]RunnerInfo, error) {
	var runners []RunnerInfo
	if err := c.getPaginatedJSON(ctx, "/runners/all", 20, &runners); err != nil {
		return nil, fmt.Errorf("listing instance runners: %w", err)
	}
	return runners, nil
}

// GetProjectMember gets a specific project member by user ID
// GET /api/v4/projects/:id/members/all/:user_id
func (c *Client) GetProjectMember(ctx context.Context, projectID int, userID string) (*ProjectMember, error) {
	path := fmt.Sprintf("/projects/%d/members/all/%s", projectID, userID)

	var member ProjectMember
	if err := c.getJSON(ctx, path, &member); err != nil {
		return nil, fmt.Errorf("getting project member: %w", err)
	}

	// Set role name based on access level
	switch member.AccessLevel {
	case 10:
		member.RoleName = "Guest"
	case 20:
		member.RoleName = "Reporter"
	case 30:
		member.RoleName = "Developer"
	case 40:
		member.RoleName = "Maintainer"
	case 50:
		member.RoleName = "Owner"
	default:
		member.RoleName = "Unknown"
	}

	return &member, nil
}

// DeleteJobLogs erases the job trace (logs) for a specific job
// POST /api/v4/projects/:id/jobs/:job_id/erase
func (c *Client) DeleteJobLogs(ctx context.Context, projectID int, jobID int) error {
	path := fmt.Sprintf("/projects/%d/jobs/%d/erase", projectID, jobID)

	resp, err := c.doRequest(ctx, "POST", path)
	if err != nil {
		return fmt.Errorf("deleting job logs: %w", err)
	}
	defer resp.Body.Close()

	return nil
}

// DeleteBranch deletes a repository branch
// DELETE /api/v4/projects/:id/repository/branches/:branch
func (c *Client) DeleteBranch(ctx context.Context, projectID int, branch string) error {
	path := fmt.Sprintf("/projects/%d/repository/branches/%s", projectID, url.PathEscape(branch))

	resp, err := c.doRequest(ctx, "DELETE", path)
	if err != nil {
		return fmt.Errorf("deleting branch: %w", err)
	}
	defer resp.Body.Close()

	return nil
}

// DeletePipeline deletes a pipeline and all associated jobs/logs
// DELETE /api/v4/projects/:id/pipelines/:pipeline_id
func (c *Client) DeletePipeline(ctx context.Context, projectID, pipelineID int) error {
	path := fmt.Sprintf("/projects/%d/pipelines/%d", projectID, pipelineID)

	resp, err := c.doRequest(ctx, "DELETE", path)
	if err != nil {
		return fmt.Errorf("deleting pipeline: %w", err)
	}
	defer resp.Body.Close()

	return nil
}

// CreateBranch creates a new branch
// POST /api/v4/projects/:id/repository/branches?branch=:name&ref=:sha
func (c *Client) CreateBranch(ctx context.Context, projectID int, branchName, ref string) error {
	path := fmt.Sprintf("/projects/%d/repository/branches?branch=%s&ref=%s",
		projectID, url.QueryEscape(branchName), url.QueryEscape(ref))

	resp, err := c.doRequest(ctx, "POST", path)
	if err != nil {
		return fmt.Errorf("creating branch: %w", err)
	}
	defer resp.Body.Close()

	return nil
}

// GetBranch gets information about a specific branch
// GET /api/v4/projects/:id/repository/branches/:branch
func (c *Client) GetBranch(ctx context.Context, projectID int, branch string) (*Branch, error) {
	path := fmt.Sprintf("/projects/%d/repository/branches/%s", projectID, url.PathEscape(branch))

	var b Branch
	if err := c.getJSON(ctx, path, &b); err != nil {
		return nil, fmt.Errorf("getting branch: %w", err)
	}

	return &b, nil
}

// CreateCommit creates a commit with file actions
// POST /api/v4/projects/:id/repository/commits
func (c *Client) CreateCommit(ctx context.Context, projectID int, branch string, actions []CommitAction, message string) (*Commit, error) {
	path := fmt.Sprintf("/projects/%d/repository/commits", projectID)

	payload := map[string]interface{}{
		"branch":         branch,
		"commit_message": message,
		"actions":        actions,
	}

	var commit Commit
	if err := c.postJSON(ctx, path, payload, &commit); err != nil {
		return nil, fmt.Errorf("creating commit: %w", err)
	}

	return &commit, nil
}

// ListPipelines lists pipelines for a project, optionally filtered by branch
// GET /api/v4/projects/:id/pipelines?ref=:branch
func (c *Client) ListPipelines(ctx context.Context, projectID int, ref string) ([]Pipeline, error) {
	path := fmt.Sprintf("/projects/%d/pipelines", projectID)
	if ref != "" {
		path += "?ref=" + url.QueryEscape(ref)
	}

	var pipelines []Pipeline
	if err := c.getPaginatedJSON(ctx, path, 20, &pipelines); err != nil {
		return nil, fmt.Errorf("listing pipelines: %w", err)
	}

	return pipelines, nil
}

// ListPipelineJobs lists jobs for a specific pipeline
// GET /api/v4/projects/:id/pipelines/:pipeline_id/jobs
func (c *Client) ListPipelineJobs(ctx context.Context, projectID, pipelineID int) ([]Job, error) {
	path := fmt.Sprintf("/projects/%d/pipelines/%d/jobs", projectID, pipelineID)

	var jobs []Job
	if err := c.getJSON(ctx, path, &jobs); err != nil {
		return nil, fmt.Errorf("listing pipeline jobs: %w", err)
	}

	return jobs, nil
}

// GetJobTrace gets the raw log output (trace) for a job
// GET /api/v4/projects/:id/jobs/:job_id/trace
func (c *Client) GetJobTrace(ctx context.Context, projectID, jobID int) (string, error) {
	path := fmt.Sprintf("/projects/%d/jobs/%d/trace", projectID, jobID)

	logs, err := c.getRaw(ctx, path)
	if err != nil {
		return "", fmt.Errorf("getting job trace: %w", err)
	}

	return string(logs), nil
}

// GetRunner fetches detailed information for a specific runner
// GET /api/v4/runners/:id
// GetRunner fetches detailed information for a specific runner
// GET /api/v4/runners/:id
func (c *Client) GetRunner(ctx context.Context, runnerID int) (*RunnerInfo, error) {
	path := fmt.Sprintf("/runners/%d", runnerID)
	var runner RunnerInfo
	if err := c.getJSON(ctx, path, &runner); err != nil {
		return nil, fmt.Errorf("getting runner details: %w", err)
	}
	return &runner, nil
}

// EnrichRunnersWithDetails fetches detailed information for each runner
// This adds platform, version, architecture, and other detailed fields
func (c *Client) EnrichRunnersWithDetails(ctx context.Context, runners []RunnerInfo) ([]RunnerInfo, error) {
	enriched := make([]RunnerInfo, 0, len(runners))
	for _, runner := range runners {
		detailed, err := c.GetRunner(ctx, runner.ID)
		if err != nil {
			// If we can't get details, keep the basic info
			enriched = append(enriched, runner)
			continue
		}
		enriched = append(enriched, *detailed)
	}
	return enriched, nil
}

// BaseURL returns the GitLab base URL for SaaS detection
func (c *Client) BaseURL() string {
	return c.baseURL
}

// ListRecentPipelines fetches recent pipelines for a project
// GET /api/v4/projects/:id/pipelines
func (c *Client) ListRecentPipelines(ctx context.Context, projectID int, limit int) ([]Pipeline, error) {
	path := fmt.Sprintf("/projects/%d/pipelines?per_page=%d&order_by=id&sort=desc", projectID, limit)

	var pipelines []Pipeline
	if err := c.getJSON(ctx, path, &pipelines); err != nil {
		return nil, fmt.Errorf("listing pipelines: %w", err)
	}

	return pipelines, nil
}
