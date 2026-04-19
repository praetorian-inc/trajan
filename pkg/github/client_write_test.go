package github

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// === Pull Request Operations Tests ===

func TestCreatePullRequest_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/repos/owner/repo/pulls", r.URL.Path)
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "Bearer test-token", r.Header.Get("Authorization"))
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		// Verify request body
		body, _ := io.ReadAll(r.Body)
		var input PullRequestInput
		json.Unmarshal(body, &input)
		assert.Equal(t, "Test PR", input.Title)
		assert.Equal(t, "feature-branch", input.Head)
		assert.Equal(t, "main", input.Base)

		w.Header().Set("X-RateLimit-Remaining", "4999")
		w.Header().Set("X-RateLimit-Limit", "5000")
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{
			"id": 12345,
			"number": 123,
			"state": "open",
			"title": "Test PR",
			"html_url": "https://github.com/owner/repo/pull/123",
			"created_at": "2026-01-06T00:00:00Z"
		}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	ctx := context.Background()

	input := PullRequestInput{
		Title: "Test PR",
		Body:  "Test description",
		Head:  "feature-branch",
		Base:  "main",
	}

	pr, err := client.CreatePullRequest(ctx, "owner", "repo", input)
	require.NoError(t, err)
	assert.NotNil(t, pr)
	assert.Equal(t, 123, pr.Number)
	assert.Equal(t, "Test PR", pr.Title)
	assert.Equal(t, "https://github.com/owner/repo/pull/123", pr.HTMLURL)
	assert.Equal(t, "open", pr.State)
}

func TestCreatePullRequest_Error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Remaining", "4999")
		w.WriteHeader(http.StatusUnprocessableEntity)
		w.Write([]byte(`{"message": "Validation Failed", "errors": [{"message": "No commits between main and feature-branch"}]}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	ctx := context.Background()

	input := PullRequestInput{
		Title: "Test PR",
		Head:  "feature-branch",
		Base:  "main",
	}

	pr, err := client.CreatePullRequest(ctx, "owner", "repo", input)
	require.Error(t, err)
	assert.Nil(t, pr)
	assert.Contains(t, err.Error(), "422")
}

func TestClosePullRequest_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/repos/owner/repo/pulls/123", r.URL.Path)
		assert.Equal(t, http.MethodPatch, r.Method)

		// Verify request body
		body, _ := io.ReadAll(r.Body)
		assert.Contains(t, string(body), `"state": "closed"`)

		w.Header().Set("X-RateLimit-Remaining", "4999")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"number": 123, "state": "closed"}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	ctx := context.Background()

	err := client.ClosePullRequest(ctx, "owner", "repo", 123)
	require.NoError(t, err)
}

// === Branch Operations Tests ===

func TestCreateBranch_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/repos/owner/repo/git/refs", r.URL.Path)
		assert.Equal(t, http.MethodPost, r.Method)

		// Verify request body
		body, _ := io.ReadAll(r.Body)
		var input map[string]string
		json.Unmarshal(body, &input)
		assert.Equal(t, "refs/heads/new-branch", input["ref"])
		assert.Equal(t, "abc123def456", input["sha"])

		w.Header().Set("X-RateLimit-Remaining", "4999")
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{
			"ref": "refs/heads/new-branch",
			"node_id": "MDM6UmVmMTI5NjI2OTpyZWZzL2hlYWRzL2ZlYXR1cmUtYQ==",
			"url": "https://api.github.com/repos/owner/repo/git/refs/heads/new-branch",
			"object": {
				"sha": "abc123def456",
				"type": "commit",
				"url": "https://api.github.com/repos/owner/repo/git/commits/abc123def456"
			}
		}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	ctx := context.Background()

	ref, err := client.CreateBranch(ctx, "owner", "repo", "new-branch", "abc123def456")
	require.NoError(t, err)
	assert.NotNil(t, ref)
	assert.Equal(t, "refs/heads/new-branch", ref.Ref)
	assert.Equal(t, "abc123def456", ref.Object.SHA)
}

func TestCreateBranch_AlreadyExists(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Remaining", "4999")
		w.WriteHeader(http.StatusUnprocessableEntity)
		w.Write([]byte(`{"message": "Reference already exists"}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	ctx := context.Background()

	ref, err := client.CreateBranch(ctx, "owner", "repo", "existing-branch", "abc123")
	require.Error(t, err)
	assert.Nil(t, ref)
	assert.Contains(t, err.Error(), "422")
}

func TestDeleteBranch_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/repos/owner/repo/git/refs/heads/old-branch", r.URL.Path)
		assert.Equal(t, http.MethodDelete, r.Method)

		w.Header().Set("X-RateLimit-Remaining", "4999")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	ctx := context.Background()

	err := client.DeleteBranch(ctx, "owner", "repo", "old-branch")
	require.NoError(t, err)
}

func TestDeleteBranch_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Remaining", "4999")
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"message": "Not Found"}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	ctx := context.Background()

	err := client.DeleteBranch(ctx, "owner", "repo", "nonexistent-branch")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "404")
}

// === File Operations Tests ===

func TestCreateOrUpdateFile_CreateNew(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/repos/owner/repo/contents/test.txt", r.URL.Path)
		assert.Equal(t, http.MethodPut, r.Method)

		// Verify request body
		body, _ := io.ReadAll(r.Body)
		var input FileContentInput
		json.Unmarshal(body, &input)
		assert.Equal(t, "Create test file", input.Message)
		assert.NotEmpty(t, input.Content)
		assert.Empty(t, input.SHA) // No SHA for new file

		w.Header().Set("X-RateLimit-Remaining", "4999")
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{
			"content": {
				"type": "file",
				"encoding": "base64",
				"size": 15,
				"name": "test.txt",
				"path": "test.txt",
				"content": "SGVsbG8gV29ybGQh",
				"sha": "abc123",
				"url": "https://api.github.com/repos/owner/repo/contents/test.txt",
				"git_url": "https://api.github.com/repos/owner/repo/git/blobs/abc123",
				"html_url": "https://github.com/owner/repo/blob/main/test.txt",
				"download_url": "https://raw.githubusercontent.com/owner/repo/main/test.txt"
			}
		}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	ctx := context.Background()

	input := FileContentInput{
		Message: "Create test file",
		Content: "SGVsbG8gV29ybGQh", // base64 encoded "Hello World!"
		Branch:  "main",
	}

	file, err := client.CreateOrUpdateFile(ctx, "owner", "repo", "test.txt", input)
	require.NoError(t, err)
	assert.NotNil(t, file)
	assert.Equal(t, "test.txt", file.Name)
	assert.Equal(t, "abc123", file.SHA)
	assert.Equal(t, 15, file.Size)
}

func TestCreateOrUpdateFile_Update(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request body includes SHA for update
		body, _ := io.ReadAll(r.Body)
		var input FileContentInput
		json.Unmarshal(body, &input)
		assert.Equal(t, "Update test file", input.Message)
		assert.Equal(t, "existing-sha-123", input.SHA) // SHA required for update

		w.Header().Set("X-RateLimit-Remaining", "4999")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{
			"content": {
				"type": "file",
				"encoding": "base64",
				"size": 20,
				"name": "test.txt",
				"path": "test.txt",
				"content": "VXBkYXRlZCBjb250ZW50",
				"sha": "def456",
				"url": "https://api.github.com/repos/owner/repo/contents/test.txt",
				"git_url": "https://api.github.com/repos/owner/repo/git/blobs/def456",
				"html_url": "https://github.com/owner/repo/blob/main/test.txt",
				"download_url": "https://raw.githubusercontent.com/owner/repo/main/test.txt"
			}
		}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	ctx := context.Background()

	input := FileContentInput{
		Message: "Update test file",
		Content: "VXBkYXRlZCBjb250ZW50", // base64 encoded "Updated content"
		SHA:     "existing-sha-123",     // SHA required for updates
		Branch:  "main",
	}

	file, err := client.CreateOrUpdateFile(ctx, "owner", "repo", "test.txt", input)
	require.NoError(t, err)
	assert.NotNil(t, file)
	assert.Equal(t, "def456", file.SHA)
	assert.Equal(t, 20, file.Size)
}

func TestDeleteFile_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/repos/owner/repo/contents/test.txt", r.URL.Path)
		assert.Equal(t, http.MethodDelete, r.Method)

		// Verify request body
		body, _ := io.ReadAll(r.Body)
		var input map[string]string
		json.Unmarshal(body, &input)
		assert.Equal(t, "Delete test file", input["message"])
		assert.Equal(t, "file-sha-123", input["sha"])
		assert.Equal(t, "main", input["branch"])

		w.Header().Set("X-RateLimit-Remaining", "4999")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"commit": {"sha": "commit-sha"}}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	ctx := context.Background()

	err := client.DeleteFile(ctx, "owner", "repo", "test.txt", "file-sha-123", "Delete test file", "main")
	require.NoError(t, err)
}

// === Collaborator Operations Tests ===

func TestInviteCollaborator_Success_Created(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/repos/owner/repo/collaborators/newuser", r.URL.Path)
		assert.Equal(t, http.MethodPut, r.Method)

		// Verify request body
		body, _ := io.ReadAll(r.Body)
		var input map[string]string
		json.Unmarshal(body, &input)
		assert.Equal(t, "push", input["permission"])

		w.Header().Set("X-RateLimit-Remaining", "4999")
		w.WriteHeader(http.StatusCreated) // 201 = new invitation
		w.Write([]byte(`{"id": 123, "state": "pending"}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	ctx := context.Background()

	err := client.InviteCollaborator(ctx, "owner", "repo", "newuser", PermissionPush)
	require.NoError(t, err)
}

func TestInviteCollaborator_Success_NoContent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Remaining", "4999")
		w.WriteHeader(http.StatusNoContent) // 204 = user already has access
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	ctx := context.Background()

	err := client.InviteCollaborator(ctx, "owner", "repo", "existinguser", PermissionAdmin)
	require.NoError(t, err)
}

func TestInviteCollaborator_Forbidden(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Remaining", "4999")
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"message": "Resource not accessible by integration"}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	ctx := context.Background()

	err := client.InviteCollaborator(ctx, "owner", "repo", "someuser", PermissionAdmin)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "403")
}

func TestRemoveCollaborator_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/repos/owner/repo/collaborators/olduser", r.URL.Path)
		assert.Equal(t, http.MethodDelete, r.Method)

		w.Header().Set("X-RateLimit-Remaining", "4999")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	ctx := context.Background()

	err := client.RemoveCollaborator(ctx, "owner", "repo", "olduser")
	require.NoError(t, err)
}

// === Workflow Operations Tests ===

func TestTriggerWorkflowDispatch_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/repos/owner/repo/actions/workflows/deploy.yml/dispatches", r.URL.Path)
		assert.Equal(t, http.MethodPost, r.Method)

		// Verify request body
		body, _ := io.ReadAll(r.Body)
		var input map[string]interface{}
		json.Unmarshal(body, &input)
		assert.Equal(t, "main", input["ref"])
		inputs, ok := input["inputs"].(map[string]interface{})
		require.True(t, ok)
		assert.Equal(t, "production", inputs["environment"])

		w.Header().Set("X-RateLimit-Remaining", "4999")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	ctx := context.Background()

	inputs := map[string]string{
		"environment": "production",
	}

	err := client.TriggerWorkflowDispatch(ctx, "owner", "repo", "deploy.yml", "main", inputs)
	require.NoError(t, err)
}

func TestTriggerWorkflowDispatch_NoInputs(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request body
		body, _ := io.ReadAll(r.Body)
		var input map[string]interface{}
		json.Unmarshal(body, &input)
		assert.Equal(t, "main", input["ref"])
		_, hasInputs := input["inputs"]
		assert.False(t, hasInputs) // No inputs field when empty

		w.Header().Set("X-RateLimit-Remaining", "4999")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	ctx := context.Background()

	err := client.TriggerWorkflowDispatch(ctx, "owner", "repo", "test.yml", "main", nil)
	require.NoError(t, err)
}

// === Repository Operations Tests ===

func TestCreateRepository_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/user/repos", r.URL.Path)
		assert.Equal(t, http.MethodPost, r.Method)

		// Verify request body
		body, _ := io.ReadAll(r.Body)
		var input CreateRepositoryInput
		json.Unmarshal(body, &input)
		assert.Equal(t, "test-repo", input.Name)
		assert.True(t, input.Private)

		w.Header().Set("X-RateLimit-Remaining", "4999")
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{
			"id": 123,
			"name": "test-repo",
			"full_name": "testuser/test-repo",
			"private": true,
			"owner": {"login": "testuser"},
			"html_url": "https://github.com/testuser/test-repo",
			"created_at": "2026-01-06T00:00:00Z"
		}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	ctx := context.Background()

	input := CreateRepositoryInput{
		Name:        "test-repo",
		Description: "Test repository",
		Private:     true,
		AutoInit:    true,
	}

	repo, err := client.CreateRepository(ctx, input)
	require.NoError(t, err)
	assert.NotNil(t, repo)
	assert.Equal(t, "test-repo", repo.Name)
	assert.True(t, repo.Private)
}

func TestDeleteRepository_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/repos/owner/old-repo", r.URL.Path)
		assert.Equal(t, http.MethodDelete, r.Method)

		w.Header().Set("X-RateLimit-Remaining", "4999")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	ctx := context.Background()

	err := client.DeleteRepository(ctx, "owner", "old-repo")
	require.NoError(t, err)
}

// === Comment Operations Tests ===

func TestCreateIssueComment_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/repos/owner/repo/issues/123/comments", r.URL.Path)
		assert.Equal(t, http.MethodPost, r.Method)

		// Verify request body
		body, _ := io.ReadAll(r.Body)
		var input map[string]string
		json.Unmarshal(body, &input)
		assert.Equal(t, "Test comment", input["body"])

		w.Header().Set("X-RateLimit-Remaining", "4999")
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{
			"id": 456,
			"body": "Test comment",
			"html_url": "https://github.com/owner/repo/issues/123#issuecomment-456",
			"created_at": "2026-01-06T00:00:00Z"
		}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	ctx := context.Background()

	comment, err := client.CreateIssueComment(ctx, "owner", "repo", 123, "Test comment")
	require.NoError(t, err)
	assert.NotNil(t, comment)
	assert.Equal(t, 456, comment.ID)
	assert.Equal(t, "Test comment", comment.Body)
}

func TestDeleteIssueComment_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/repos/owner/repo/issues/comments/456", r.URL.Path)
		assert.Equal(t, http.MethodDelete, r.Method)

		w.Header().Set("X-RateLimit-Remaining", "4999")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	ctx := context.Background()

	err := client.DeleteIssueComment(ctx, "owner", "repo", 456)
	require.NoError(t, err)
}

// === GetRef Tests (used by CreateBranch) ===

func TestGetRef_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/repos/owner/repo/git/refs/heads/main", r.URL.Path)
		assert.Equal(t, http.MethodGet, r.Method)

		w.Header().Set("X-RateLimit-Remaining", "4999")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{
			"ref": "refs/heads/main",
			"node_id": "MDM6UmVmMTI5NjI2OTpyZWZzL2hlYWRzL21haW4=",
			"url": "https://api.github.com/repos/owner/repo/git/refs/heads/main",
			"object": {
				"sha": "abc123def456",
				"type": "commit",
				"url": "https://api.github.com/repos/owner/repo/git/commits/abc123def456"
			}
		}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	ctx := context.Background()

	ref, err := client.GetRef(ctx, "owner", "repo", "heads/main")
	require.NoError(t, err)
	assert.NotNil(t, ref)
	assert.Equal(t, "refs/heads/main", ref.Ref)
	assert.Equal(t, "abc123def456", ref.Object.SHA)
}

func TestGetRef_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Remaining", "4999")
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"message": "Not Found"}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	ctx := context.Background()

	ref, err := client.GetRef(ctx, "owner", "repo", "heads/nonexistent")
	require.Error(t, err)
	assert.Nil(t, ref)
}

// === Additional Error Cases ===

func TestClosePullRequest_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Remaining", "4999")
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"message": "Not Found"}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	ctx := context.Background()

	err := client.ClosePullRequest(ctx, "owner", "repo", 999)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "404")
}

func TestCreateOrUpdateFile_Error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Remaining", "4999")
		w.WriteHeader(http.StatusConflict)
		w.Write([]byte(`{"message": "SHA does not match"}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	ctx := context.Background()

	input := FileContentInput{
		Message: "Update file",
		Content: "dGVzdA==",
		SHA:     "wrong-sha",
	}

	file, err := client.CreateOrUpdateFile(ctx, "owner", "repo", "test.txt", input)
	require.Error(t, err)
	assert.Nil(t, file)
	assert.Contains(t, err.Error(), "409")
}

func TestDeleteFile_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Remaining", "4999")
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"message": "Not Found"}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	ctx := context.Background()

	err := client.DeleteFile(ctx, "owner", "repo", "nonexistent.txt", "sha", "Delete", "main")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "deleting file failed")
}

func TestTriggerWorkflowDispatch_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Remaining", "4999")
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"message": "Not Found"}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	ctx := context.Background()

	err := client.TriggerWorkflowDispatch(ctx, "owner", "repo", "nonexistent.yml", "main", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "404")
}

func TestRemoveCollaborator_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Remaining", "4999")
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"message": "Not Found"}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	ctx := context.Background()

	err := client.RemoveCollaborator(ctx, "owner", "repo", "nonexistent")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "404")
}

func TestCreateRepository_Error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Remaining", "4999")
		w.WriteHeader(http.StatusUnprocessableEntity)
		w.Write([]byte(`{"message": "Repository creation failed. Name already exists"}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	ctx := context.Background()

	input := CreateRepositoryInput{
		Name:    "existing-repo",
		Private: true,
	}

	repo, err := client.CreateRepository(ctx, input)
	require.Error(t, err)
	assert.Nil(t, repo)
	assert.Contains(t, err.Error(), "422")
}

func TestDeleteRepository_Forbidden(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Remaining", "4999")
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"message": "Must have admin rights to Repository"}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	ctx := context.Background()

	err := client.DeleteRepository(ctx, "owner", "protected-repo")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "403")
}

func TestCreateIssueComment_Error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Remaining", "4999")
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"message": "Not Found"}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	ctx := context.Background()

	comment, err := client.CreateIssueComment(ctx, "owner", "repo", 999, "Comment on nonexistent issue")
	require.Error(t, err)
	assert.Nil(t, comment)
}

// === Context Cancellation Tests ===

func TestCreatePullRequest_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Delay to allow cancellation to happen during request
		time.Sleep(50 * time.Millisecond)
		cancel() // Cancel during request
		time.Sleep(50 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")

	input := PullRequestInput{
		Title: "Test PR",
		Head:  "feature",
		Base:  "main",
	}

	_, err := client.CreatePullRequest(ctx, "owner", "repo", input)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "context canceled")
}

func TestCreateBranch_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(50 * time.Millisecond)
		cancel() // Cancel during request
		time.Sleep(50 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")

	_, err := client.CreateBranch(ctx, "owner", "repo", "new-branch", "abc123")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "context canceled")
}

func TestCreateOrUpdateFile_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(50 * time.Millisecond)
		cancel() // Cancel during request
		time.Sleep(50 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")

	input := FileContentInput{
		Message: "Test",
		Content: "dGVzdA==",
	}

	_, err := client.CreateOrUpdateFile(ctx, "owner", "repo", "test.txt", input)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "context canceled")
}

func TestInviteCollaborator_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(50 * time.Millisecond)
		cancel() // Cancel during request
		time.Sleep(50 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")

	err := client.InviteCollaborator(ctx, "owner", "repo", "user", PermissionPush)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "context canceled")
}

func TestTriggerWorkflowDispatch_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(50 * time.Millisecond)
		cancel() // Cancel during request
		time.Sleep(50 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")

	err := client.TriggerWorkflowDispatch(ctx, "owner", "repo", "test.yml", "main", nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "context canceled")
}

// === Rate Limit Handling Tests ===

func TestClient_RateLimitBackoff(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts == 1 {
			// First request: rate limited with Retry-After
			w.Header().Set("Retry-After", "1")
			w.Header().Set("X-RateLimit-Remaining", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte(`{"message": "API rate limit exceeded"}`))
			return
		}
		// Second request: success
		w.Header().Set("X-RateLimit-Remaining", "4999")
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"id": 123, "number": 1, "state": "open"}`))
	}))
	defer server.Close()

	start := time.Now()
	client := NewClient(server.URL, "test-token")
	ctx := context.Background()

	input := PullRequestInput{
		Title: "Test PR",
		Head:  "feature",
		Base:  "main",
	}

	// First request will fail with 429, second request should succeed after backoff
	_, err := client.CreatePullRequest(ctx, "owner", "repo", input)

	// First request should fail (429)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "429")
	assert.Equal(t, 1, attempts)

	// Second request should succeed after waiting for Retry-After
	_, err = client.CreatePullRequest(ctx, "owner", "repo", input)
	elapsed := time.Since(start)

	require.NoError(t, err)
	assert.GreaterOrEqual(t, elapsed, 1*time.Second) // Should have waited
	assert.Equal(t, 2, attempts)                     // Should have retried
}

func TestClient_RespectXRateLimitRemaining(t *testing.T) {
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		// Set rate limit to trigger 5% threshold (250 remaining out of 5000)
		w.Header().Set("X-RateLimit-Remaining", "200") // Below 5% threshold
		w.Header().Set("X-RateLimit-Limit", "5000")
		w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(time.Now().Add(10*time.Minute).Unix(), 10))
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"id": 123, "number": 1, "state": "open"}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	input := PullRequestInput{
		Title: "Test PR",
		Head:  "feature",
		Base:  "main",
	}

	// First request sets remaining to 200 (below 5% threshold)
	_, err := client.CreatePullRequest(ctx, "owner", "repo", input)
	require.NoError(t, err)

	// Second request should be throttled (would wait until reset time)
	// We use a short timeout to verify throttling is triggered
	_, err = client.CreatePullRequest(ctx, "owner", "repo", input)

	// Should timeout waiting for rate limit reset
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "context deadline exceeded")
	assert.Equal(t, 1, requestCount) // Only first request went through
}

func TestClient_RetryAfterHeader(t *testing.T) {
	requestTimes := []time.Time{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestTimes = append(requestTimes, time.Now())
		if len(requestTimes) == 1 {
			// First request: set Retry-After to 1 second
			w.Header().Set("Retry-After", "1")
			w.Header().Set("X-RateLimit-Remaining", "4999")
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte(`{"id": 123, "number": 1, "state": "open"}`))
			return
		}
		// Second request: should arrive after retry-after delay
		w.Header().Set("X-RateLimit-Remaining", "4998")
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"id": 124, "number": 2, "state": "open"}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	ctx := context.Background()

	input := PullRequestInput{
		Title: "Test PR",
		Head:  "feature",
		Base:  "main",
	}

	// First request
	_, err := client.CreatePullRequest(ctx, "owner", "repo", input)
	require.NoError(t, err)

	// Second request should wait for Retry-After
	_, err = client.CreatePullRequest(ctx, "owner", "repo", input)
	require.NoError(t, err)

	// Verify second request was delayed by at least 1 second
	assert.Equal(t, 2, len(requestTimes))
	timeDiff := requestTimes[1].Sub(requestTimes[0])
	assert.GreaterOrEqual(t, timeDiff, 1*time.Second)
}
