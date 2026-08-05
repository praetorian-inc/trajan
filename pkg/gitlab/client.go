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

type Client struct {
	httpClient  *http.Client
	baseURL     string
	token       string
	rateLimiter *RateLimiter
	semaphore   *semaphore.Weighted

	// Cached to avoid a GetProject call per template lookup.
	templatesProjectID   *int
	templatesProjectLock sync.RWMutex
}

// Prevents token leakage when a Client is logged.
func (c *Client) String() string {
	if c == nil {
		return "Client{nil}"
	}

	return fmt.Sprintf("Client{baseURL: %q, token: [REDACTED], rateLimiter: %+v}",
		c.baseURL,
		c.rateLimiter,
	)
}

// Prevents token leakage under %#v.
func (c *Client) GoString() string {
	if c == nil {
		return "(*Client)(nil)"
	}

	return fmt.Sprintf("&Client{baseURL: %q, token: [REDACTED], rateLimiter: %#v}",
		c.baseURL,
		c.rateLimiter,
	)
}

type ClientOption func(*Client)

func WithTimeout(timeout time.Duration) ClientOption {
	return func(c *Client) {
		c.httpClient.Timeout = timeout
	}
}

func WithConcurrency(maxVal int64) ClientOption {
	return func(c *Client) {
		if maxVal > 0 {
			c.semaphore = semaphore.NewWeighted(maxVal)
		}
	}
}

func WithHTTPTransport(transport http.RoundTripper) ClientOption {
	return func(c *Client) {
		c.httpClient.Transport = transport
	}
}

func NewClient(baseURL, token string, opts ...ClientOption) *Client {
	if baseURL == "" {
		baseURL = DefaultBaseURL
	} else if !strings.HasSuffix(baseURL, "/api/v4") {
		// Callers pass a bare instance URL for self-hosted GitLab.
		baseURL = strings.TrimRight(baseURL, "/") + "/api/v4"
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

	for _, opt := range opts {
		opt(c)
	}

	return c
}

func (c *Client) GetProject(ctx context.Context, projectPath string) (*Project, error) {
	// GitLab takes the project path as :id, URL-encoded ("owner/repo" -> "owner%2Frepo").
	encodedPath := url.PathEscape(projectPath)
	path := fmt.Sprintf("/projects/%s", encodedPath)

	var project Project
	if err := c.getJSON(ctx, path, &project); err != nil {
		return nil, fmt.Errorf("getting project: %w", err)
	}

	return &project, nil
}

func (c *Client) ListGroupProjects(ctx context.Context, groupName string) ([]Project, error) {
	encodedGroup := url.PathEscape(groupName)
	path := fmt.Sprintf("/groups/%s/projects", encodedGroup)

	var projects []Project
	if err := c.getPaginatedJSON(ctx, path, 20, &projects); err != nil {
		return nil, fmt.Errorf("listing group projects: %w", err)
	}

	return projects, nil
}

func (c *Client) ListUserProjects(ctx context.Context, username string) ([]Project, error) {
	path := fmt.Sprintf("/users/%s/projects", url.PathEscape(username))

	var projects []Project
	if err := c.getPaginatedJSON(ctx, path, 20, &projects); err != nil {
		return nil, fmt.Errorf("listing user projects: %w", err)
	}

	return projects, nil
}

// ref should be a branch name, tag, or commit SHA
func (c *Client) GetWorkflowFile(ctx context.Context, projectID int, filePath, ref string) ([]byte, error) {
	encodedPath := url.PathEscape(filePath)
	apiPath := fmt.Sprintf("/projects/%d/repository/files/%s?ref=%s", projectID, encodedPath, url.QueryEscape(ref))

	var fileResp FileResponse
	if err := c.getJSON(ctx, apiPath, &fileResp); err != nil {
		return nil, fmt.Errorf("getting workflow file: %w", err)
	}

	if fileResp.Encoding == "base64" {
		return decodeBase64(fileResp.Content)
	}

	return []byte(fileResp.Content), nil
}

func (c *Client) GetTemplate(ctx context.Context, templateName string) ([]byte, error) {
	const (
		templatesProject = "gitlab-org/gitlab"
		templatesPath    = "lib/gitlab/ci/templates"
		templatesBranch  = "master"
	)

	filePath := fmt.Sprintf("%s/%s", templatesPath, templateName)

	// Lazy-load with double-checked locking.
	c.templatesProjectLock.RLock()
	projectID := c.templatesProjectID
	c.templatesProjectLock.RUnlock()

	if projectID == nil {
		c.templatesProjectLock.Lock()
		if c.templatesProjectID == nil {
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

func decodeBase64(s string) ([]byte, error) {
	// GitLab returns content with newlines
	s = strings.ReplaceAll(s, "\n", "")
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("decoding base64: %w", err)
	}
	return decoded, nil
}

func (c *Client) GetUser(ctx context.Context) (*User, error) {
	var user User
	if err := c.getJSON(ctx, "/user", &user); err != nil {
		return nil, fmt.Errorf("getting user: %w", err)
	}
	return &user, nil
}

// May fail for project or group tokens and for older GitLab versions.
func (c *Client) GetPersonalAccessToken(ctx context.Context) (*PersonalAccessToken, error) {
	var pat PersonalAccessToken
	if err := c.getJSON(ctx, "/personal_access_tokens/self", &pat); err != nil {
		return nil, fmt.Errorf("getting personal access token: %w", err)
	}
	return &pat, nil
}

func (c *Client) ListGroups(ctx context.Context) ([]Group, error) {
	var groups []Group
	if err := c.getPaginatedJSON(ctx, "/groups", 20, &groups); err != nil {
		return nil, fmt.Errorf("listing groups: %w", err)
	}
	return groups, nil
}

func (c *Client) ListAllProjects(ctx context.Context) ([]Project, error) {
	var projects []Project
	if err := c.getPaginatedJSON(ctx, "/projects", 20, &projects); err != nil {
		return nil, fmt.Errorf("listing projects: %w", err)
	}
	return projects, nil
}

func (c *Client) ListMemberProjects(ctx context.Context) ([]Project, error) {
	var projects []Project
	if err := c.getPaginatedJSON(ctx, "/projects?membership=true", 20, &projects); err != nil {
		return nil, fmt.Errorf("listing member projects: %w", err)
	}
	return projects, nil
}

func (c *Client) ListProjectMembers(ctx context.Context, projectID int) ([]Member, error) {
	path := fmt.Sprintf("/projects/%d/members", projectID)
	var members []Member
	if err := c.getJSON(ctx, path, &members); err != nil {
		return nil, fmt.Errorf("listing project members: %w", err)
	}
	return members, nil
}

// Deprecated: Use ListPipelines with empty ref instead for new code
func (c *Client) ListProjectPipelines(ctx context.Context, projectID int) ([]Pipeline, error) {
	return c.ListPipelines(ctx, projectID, "")
}

func (c *Client) ListProjectVariables(ctx context.Context, projectID int) ([]Variable, error) {
	path := fmt.Sprintf("/projects/%d/variables", projectID)
	var variables []Variable
	if err := c.getPaginatedJSON(ctx, path, 20, &variables); err != nil {
		return nil, fmt.Errorf("listing project variables: %w", err)
	}
	return variables, nil
}

func (c *Client) ListGroupMembers(ctx context.Context, groupID int) ([]Member, error) {
	path := fmt.Sprintf("/groups/%d/members", groupID)
	var members []Member
	if err := c.getJSON(ctx, path, &members); err != nil {
		return nil, fmt.Errorf("listing group members: %w", err)
	}
	return members, nil
}

func (c *Client) GetProjectAccessLevel(ctx context.Context, projectID, userID int) (int, error) {
	path := fmt.Sprintf("/projects/%d/members/%d", projectID, userID)
	var member Member
	if err := c.getJSON(ctx, path, &member); err != nil {
		return 0, fmt.Errorf("getting project access level: %w", err)
	}
	return member.AccessLevel, nil
}

func (c *Client) GetGroupAccessLevel(ctx context.Context, groupID, userID int) (int, error) {
	path := fmt.Sprintf("/groups/%d/members/%d", groupID, userID)
	var member Member
	if err := c.getJSON(ctx, path, &member); err != nil {
		return 0, fmt.Errorf("getting group access level: %w", err)
	}
	return member.AccessLevel, nil
}

func (c *Client) RateLimiter() *RateLimiter {
	return c.rateLimiter
}

func (c *Client) GetGroup(ctx context.Context, groupPath string) (*Group, error) {
	encodedPath := url.PathEscape(groupPath)
	path := fmt.Sprintf("/groups/%s", encodedPath)

	var group Group
	if err := c.getJSON(ctx, path, &group); err != nil {
		return nil, fmt.Errorf("getting group: %w", err)
	}
	return &group, nil
}

func (c *Client) ListSubgroups(ctx context.Context, groupID int) ([]Group, error) {
	path := fmt.Sprintf("/groups/%d/subgroups", groupID)
	var groups []Group
	if err := c.getPaginatedJSON(ctx, path, 20, &groups); err != nil {
		return nil, fmt.Errorf("listing subgroups: %w", err)
	}
	return groups, nil
}

func (c *Client) ListSharedGroups(ctx context.Context, groupID int) ([]SharedGroup, error) {
	path := fmt.Sprintf("/groups/%d/groups/shared", groupID)
	var groups []SharedGroup
	if err := c.getPaginatedJSON(ctx, path, 20, &groups); err != nil {
		return nil, fmt.Errorf("listing shared groups: %w", err)
	}
	return groups, nil
}

func (c *Client) ListGroupVariables(ctx context.Context, groupID int) ([]Variable, error) {
	path := fmt.Sprintf("/groups/%d/variables", groupID)
	var variables []Variable
	if err := c.getPaginatedJSON(ctx, path, 20, &variables); err != nil {
		// 403 is expected for non-maintainers; anything else propagates.
		if IsPermissionError(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("listing group variables: %w", err)
	}
	return variables, nil
}

// Requires admin access.
func (c *Client) ListInstanceVariables(ctx context.Context) ([]Variable, error) {
	var variables []Variable
	if err := c.getJSON(ctx, "/admin/ci/variables", &variables); err != nil {
		// 403 is expected for non-admins; anything else propagates.
		if IsPermissionError(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("listing instance variables: %w", err)
	}
	return variables, nil
}

func (c *Client) ListProtectedBranches(ctx context.Context, projectID int) ([]BranchProtection, error) {
	path := fmt.Sprintf("/projects/%d/protected_branches", projectID)
	var protections []BranchProtection
	if err := c.getPaginatedJSON(ctx, path, 20, &protections); err != nil {
		return nil, fmt.Errorf("listing protected branches: %w", err)
	}
	return protections, nil
}

func (c *Client) ListProjectRunners(ctx context.Context, projectID int) ([]RunnerInfo, error) {
	path := fmt.Sprintf("/projects/%d/runners", projectID)
	var runners []RunnerInfo
	if err := c.getPaginatedJSON(ctx, path, 20, &runners); err != nil {
		return nil, fmt.Errorf("listing project runners: %w", err)
	}
	return runners, nil
}

func (c *Client) ListGroupRunners(ctx context.Context, groupID int) ([]RunnerInfo, error) {
	path := fmt.Sprintf("/groups/%d/runners", groupID)
	var runners []RunnerInfo
	if err := c.getPaginatedJSON(ctx, path, 20, &runners); err != nil {
		return nil, fmt.Errorf("listing group runners: %w", err)
	}
	return runners, nil
}

// Requires admin access.
func (c *Client) ListInstanceRunners(ctx context.Context) ([]RunnerInfo, error) {
	var runners []RunnerInfo
	if err := c.getPaginatedJSON(ctx, "/runners/all", 20, &runners); err != nil {
		return nil, fmt.Errorf("listing instance runners: %w", err)
	}
	return runners, nil
}

func (c *Client) GetProjectMember(ctx context.Context, projectID int, userID string) (*ProjectMember, error) {
	path := fmt.Sprintf("/projects/%d/members/all/%s", projectID, userID)

	var member ProjectMember
	if err := c.getJSON(ctx, path, &member); err != nil {
		return nil, fmt.Errorf("getting project member: %w", err)
	}

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

func (c *Client) DeleteJobLogs(ctx context.Context, projectID int, jobID int) error {
	path := fmt.Sprintf("/projects/%d/jobs/%d/erase", projectID, jobID)

	resp, err := c.doRequest(ctx, "POST", path)
	if err != nil {
		return fmt.Errorf("deleting job logs: %w", err)
	}
	defer resp.Body.Close()

	return nil
}

func (c *Client) DeleteBranch(ctx context.Context, projectID int, branch string) error {
	path := fmt.Sprintf("/projects/%d/repository/branches/%s", projectID, url.PathEscape(branch))

	resp, err := c.doRequest(ctx, "DELETE", path)
	if err != nil {
		return fmt.Errorf("deleting branch: %w", err)
	}
	defer resp.Body.Close()

	return nil
}

// Deleting a pipeline also removes its jobs and their logs.
func (c *Client) DeletePipeline(ctx context.Context, projectID, pipelineID int) error {
	path := fmt.Sprintf("/projects/%d/pipelines/%d", projectID, pipelineID)

	resp, err := c.doRequest(ctx, "DELETE", path)
	if err != nil {
		return fmt.Errorf("deleting pipeline: %w", err)
	}
	defer resp.Body.Close()

	return nil
}

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

func (c *Client) GetBranch(ctx context.Context, projectID int, branch string) (*Branch, error) {
	path := fmt.Sprintf("/projects/%d/repository/branches/%s", projectID, url.PathEscape(branch))

	var b Branch
	if err := c.getJSON(ctx, path, &b); err != nil {
		return nil, fmt.Errorf("getting branch: %w", err)
	}

	return &b, nil
}

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

func (c *Client) ListPipelineJobs(ctx context.Context, projectID, pipelineID int) ([]Job, error) {
	path := fmt.Sprintf("/projects/%d/pipelines/%d/jobs", projectID, pipelineID)

	var jobs []Job
	if err := c.getJSON(ctx, path, &jobs); err != nil {
		return nil, fmt.Errorf("listing pipeline jobs: %w", err)
	}

	return jobs, nil
}

func (c *Client) GetJobTrace(ctx context.Context, projectID, jobID int) (string, error) {
	path := fmt.Sprintf("/projects/%d/jobs/%d/trace", projectID, jobID)

	logs, err := c.getRaw(ctx, path)
	if err != nil {
		return "", fmt.Errorf("getting job trace: %w", err)
	}

	return string(logs), nil
}

func (c *Client) GetRunner(ctx context.Context, runnerID int) (*RunnerInfo, error) {
	path := fmt.Sprintf("/runners/%d", runnerID)
	var runner RunnerInfo
	if err := c.getJSON(ctx, path, &runner); err != nil {
		return nil, fmt.Errorf("getting runner details: %w", err)
	}
	return &runner, nil
}

// The list endpoints omit platform, version and architecture; the per-runner endpoint has them.
func (c *Client) EnrichRunnersWithDetails(ctx context.Context, runners []RunnerInfo) ([]RunnerInfo, error) {
	enriched := make([]RunnerInfo, 0, len(runners))
	for i := range runners {
		runner := &runners[i]
		detailed, err := c.GetRunner(ctx, runner.ID)
		if err != nil {
			// A failed detail fetch must not drop the runner.
			enriched = append(enriched, *runner)
			continue
		}
		enriched = append(enriched, *detailed)
	}
	return enriched, nil
}

func (c *Client) BaseURL() string {
	return c.baseURL
}

func (c *Client) ListRecentPipelines(ctx context.Context, projectID int, limit int) ([]Pipeline, error) {
	path := fmt.Sprintf("/projects/%d/pipelines?per_page=%d&order_by=id&sort=desc", projectID, limit)

	var pipelines []Pipeline
	if err := c.getJSON(ctx, path, &pipelines); err != nil {
		return nil, fmt.Errorf("listing pipelines: %w", err)
	}

	return pipelines, nil
}
