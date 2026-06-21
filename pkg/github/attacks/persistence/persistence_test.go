package persistence

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/praetorian-inc/trajan/pkg/attacks"
	"github.com/praetorian-inc/trajan/pkg/detections"
	"github.com/praetorian-inc/trajan/pkg/github"
	"github.com/praetorian-inc/trajan/pkg/platforms"
)

func TestNew(t *testing.T) {
	plugin := New()
	if plugin == nil {
		t.Fatal("New() returned nil")
	}

	if plugin.Name() != "persistence" {
		t.Errorf("Name() = %q, want %q", plugin.Name(), "persistence")
	}

	if plugin.Category() != attacks.CategoryPersistence {
		t.Errorf("Category() = %q, want %q", plugin.Category(), attacks.CategoryPersistence)
	}

	if plugin.Platform() != "github" {
		t.Errorf("Platform() = %q, want %q", plugin.Platform(), "github")
	}
}

func TestCanAttack(t *testing.T) {
	plugin := New()

	tests := []struct {
		name     string
		findings []detections.Finding
		want     bool
	}{
		{
			name: "actions injection vulnerability",
			findings: []detections.Finding{
				{
					Type: detections.VulnActionsInjection,
				},
			},
			want: true,
		},
		{
			name: "pwn_request vulnerability",
			findings: []detections.Finding{
				{
					Type: detections.VulnPwnRequest,
				},
			},
			want: true,
		},
		{
			name: "self-hosted runner vulnerability",
			findings: []detections.Finding{
				{
					Type: detections.VulnSelfHostedRunner,
				},
			},
			want: true,
		},
		{
			name: "no relevant findings",
			findings: []detections.Finding{
				{
					Type: detections.VulnExcessivePermissions,
				},
			},
			want: false,
		},
		{
			name:     "empty findings",
			findings: []detections.Finding{},
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := plugin.CanAttack(tt.findings)
			if got != tt.want {
				t.Errorf("CanAttack() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGenerateSSHKeyPair(t *testing.T) {
	publicKey, privateKey, err := generateSSHKeyPair()
	if err != nil {
		t.Fatalf("generateSSHKeyPair() error = %v", err)
	}

	if publicKey == "" {
		t.Error("publicKey is empty")
	}

	if privateKey == "" {
		t.Error("privateKey is empty")
	}

	// Check that public key starts with ssh-rsa
	if len(publicKey) < 7 || publicKey[:7] != "ssh-rsa" {
		t.Errorf("publicKey does not start with 'ssh-rsa': %q", publicKey[:min(20, len(publicKey))])
	}

	// Check that private key is PEM formatted
	pemHeader := "-----BEGIN RSA PRIVATE KEY-----"
	if len(privateKey) < len(pemHeader) || privateKey[:len(pemHeader)] != pemHeader {
		t.Errorf("privateKey does not start with PEM header: %q", privateKey[:min(35, len(privateKey))])
	}
}

func TestExecute_DryRun_DeployKey(t *testing.T) {
	plugin := New()

	mockPlatform := newMockGitHubPlatform(t)
	defer mockPlatform.Close()

	opts := attacks.AttackOptions{
		Target:    platforms.Target{Type: platforms.TargetRepo, Value: "owner/repo"},
		Platform:  mockPlatform.Platform,
		DryRun:    true,
		SessionID: "test-session",
		ExtraOpts: map[string]string{
			"method": "deploy_key",
		},
	}

	result, err := plugin.Execute(context.Background(), opts)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	if !result.Success {
		t.Errorf("Execute() Success = %v, want true", result.Success)
	}

	if result.Message != "[DRY RUN] Would add deploy key" {
		t.Errorf("Execute() Message = %q, want %q", result.Message, "[DRY RUN] Would add deploy key")
	}

	if len(result.Artifacts) != 1 {
		t.Errorf("Execute() len(Artifacts) = %d, want 1", len(result.Artifacts))
	}

	if len(result.Artifacts) > 0 && result.Artifacts[0].Type != attacks.ArtifactFile {
		t.Errorf("Execute() Artifact[0].Type = %v, want %v", result.Artifacts[0].Type, attacks.ArtifactFile)
	}
}

func TestExecute_DryRun_MaliciousWorkflow(t *testing.T) {
	plugin := New()

	mockPlatform := newMockGitHubPlatform(t)
	defer mockPlatform.Close()

	opts := attacks.AttackOptions{
		Target:    platforms.Target{Type: platforms.TargetRepo, Value: "owner/repo"},
		Platform:  mockPlatform.Platform,
		DryRun:    true,
		SessionID: "test-session",
		ExtraOpts: map[string]string{
			"method": "malicious_workflow",
			"c2_url": "https://test.example.com/callback",
		},
	}

	result, err := plugin.Execute(context.Background(), opts)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	if !result.Success {
		t.Errorf("Execute() Success = %v, want true", result.Success)
	}

	if result.Message != "[DRY RUN] Would add malicious workflow" {
		t.Errorf("Execute() Message = %q, want %q", result.Message, "[DRY RUN] Would add malicious workflow")
	}

	// Should have 3 artifacts: branch, workflow, PR
	if len(result.Artifacts) != 3 {
		t.Errorf("Execute() len(Artifacts) = %d, want 3", len(result.Artifacts))
	}

	// Verify artifact types
	expectedTypes := map[attacks.ArtifactType]bool{
		attacks.ArtifactBranch:   true,
		attacks.ArtifactWorkflow: true,
		attacks.ArtifactPR:       true,
	}

	for _, artifact := range result.Artifacts {
		if !expectedTypes[artifact.Type] {
			t.Errorf("Unexpected artifact type: %v", artifact.Type)
		}
	}
}

func TestExecute_DryRun_Collaborator(t *testing.T) {
	plugin := New()

	mockPlatform := newMockGitHubPlatform(t)
	defer mockPlatform.Close()

	opts := attacks.AttackOptions{
		Target:    platforms.Target{Type: platforms.TargetRepo, Value: "owner/repo"},
		Platform:  mockPlatform.Platform,
		DryRun:    true,
		SessionID: "test-session",
		ExtraOpts: map[string]string{
			"method":     "collaborator",
			"username":   "testuser",
			"permission": "admin",
		},
	}

	result, err := plugin.Execute(context.Background(), opts)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	if !result.Success {
		t.Errorf("Execute() Success = %v, want true", result.Success)
	}

	expectedMsg := "[DRY RUN] Would invite testuser as admin collaborator"
	if result.Message != expectedMsg {
		t.Errorf("Execute() Message = %q, want %q", result.Message, expectedMsg)
	}

	if len(result.Artifacts) != 1 {
		t.Errorf("Execute() len(Artifacts) = %d, want 1", len(result.Artifacts))
	}

	if len(result.Artifacts) > 0 {
		artifact := result.Artifacts[0]
		if artifact.Type != attacks.ArtifactFile {
			t.Errorf("Execute() Artifact[0].Type = %v, want %v", artifact.Type, attacks.ArtifactFile)
		}
		if artifact.Identifier != "collaborator_testuser" {
			t.Errorf("Execute() Artifact[0].Identifier = %q, want %q", artifact.Identifier, "collaborator_testuser")
		}
	}
}

func TestExecute_InvalidPlatform(t *testing.T) {
	plugin := New()

	// Use a non-GitHub platform (mock with wrong type)
	invalidPlatform := &invalidPlatform{}

	opts := attacks.AttackOptions{
		Target:    platforms.Target{Type: platforms.TargetRepo, Value: "owner/repo"},
		Platform:  invalidPlatform,
		DryRun:    true,
		SessionID: "test-session",
		ExtraOpts: map[string]string{
			"method": "deploy_key",
		},
	}

	result, err := plugin.Execute(context.Background(), opts)

	if err == nil {
		t.Error("Execute() expected error for invalid platform, got nil")
	}

	if result == nil {
		t.Fatal("Execute() result is nil")
	}

	if result.Success {
		t.Error("Execute() Success = true, want false for invalid platform")
	}

	if result.Message != "platform is not GitHub" {
		t.Errorf("Execute() Message = %q, want %q", result.Message, "platform is not GitHub")
	}
}

func TestExecute_InvalidTarget(t *testing.T) {
	plugin := New()

	mockPlatform := newMockGitHubPlatform(t)
	defer mockPlatform.Close()

	opts := attacks.AttackOptions{
		Target:    platforms.Target{Type: platforms.TargetRepo, Value: "invalid-target-format"},
		Platform:  mockPlatform.Platform,
		DryRun:    true,
		SessionID: "test-session",
		ExtraOpts: map[string]string{
			"method": "deploy_key",
		},
	}

	result, err := plugin.Execute(context.Background(), opts)

	if err == nil {
		t.Error("Execute() expected error for invalid target, got nil")
	}

	if result == nil {
		t.Fatal("Execute() result is nil")
	}

	if result.Success {
		t.Error("Execute() Success = true, want false for invalid target")
	}
}

func TestCleanupActions(t *testing.T) {
	plugin := New()

	tests := []struct {
		name             string
		method           string
		wantCleanupCount int
		wantCleanupTypes []attacks.ArtifactType
	}{
		{
			name:             "deploy_key cleanup",
			method:           "deploy_key",
			wantCleanupCount: 0, // Dry run doesn't set cleanup actions
		},
		{
			name:             "malicious_workflow cleanup",
			method:           "malicious_workflow",
			wantCleanupCount: 0, // Dry run doesn't set cleanup actions
		},
		{
			name:             "collaborator cleanup",
			method:           "collaborator",
			wantCleanupCount: 0, // Dry run doesn't set cleanup actions
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockPlatform := newMockGitHubPlatform(t)
			defer mockPlatform.Close()

			opts := attacks.AttackOptions{
				Target:    platforms.Target{Type: platforms.TargetRepo, Value: "owner/repo"},
				Platform:  mockPlatform.Platform,
				DryRun:    true,
				SessionID: "test-session",
				ExtraOpts: map[string]string{
					"method":     tt.method,
					"username":   "testuser",
					"permission": "admin",
				},
			}

			result, err := plugin.Execute(context.Background(), opts)
			if err != nil {
				t.Fatalf("Execute() error = %v", err)
			}

			if len(result.CleanupActions) != tt.wantCleanupCount {
				t.Errorf("Execute() len(CleanupActions) = %d, want %d", len(result.CleanupActions), tt.wantCleanupCount)
			}
		})
	}
}

// Mock implementations for testing

type mockPlatform struct {
	*github.Platform
	server *httptest.Server
}

func newMockGitHubPlatform(t *testing.T) *mockPlatform {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"default_branch": "main", "owner": {"login": "owner"}, "name": "repo"}`))
	}))

	platform := github.NewPlatform()
	ctx := context.Background()
	if err := platform.Init(ctx, platforms.Config{
		Token:   "test-token",
		BaseURL: server.URL,
	}); err != nil {
		t.Fatalf("Failed to init platform: %v", err)
	}

	return &mockPlatform{
		Platform: platform,
		server:   server,
	}
}

func (m *mockPlatform) Close() {
	m.server.Close()
}

func TestExecute_RealMode_DeployKey(t *testing.T) {
	plugin := New()

	// Create mock server with comprehensive API responses
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch {
		case r.URL.Path == "/repos/owner/repo":
			// Repository info
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"default_branch": "main", "owner": {"login": "owner"}, "name": "repo"}`))
		case r.URL.Path == "/repos/owner/repo/keys" && r.Method == "POST":
			// Deploy key creation
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte(`{"id": 12345, "title": "trajan-persist-test-session", "read_only": false}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	platform := github.NewPlatform()
	ctx := context.Background()
	if err := platform.Init(ctx, platforms.Config{
		Token:   "test-token",
		BaseURL: server.URL,
	}); err != nil {
		t.Fatalf("Failed to init platform: %v", err)
	}

	opts := attacks.AttackOptions{
		Target:    platforms.Target{Type: platforms.TargetRepo, Value: "owner/repo"},
		Platform:  platform,
		DryRun:    false, // IMPORTANT: Not dry-run
		SessionID: "test-session",
		ExtraOpts: map[string]string{
			"method": "deploy_key",
		},
	}

	result, err := plugin.Execute(ctx, opts)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	if !result.Success {
		t.Errorf("Execute() Success = %v, want true", result.Success)
	}

	if result.Message != "Deploy key persistence established" {
		t.Errorf("Execute() Message = %q, want %q", result.Message, "Deploy key persistence established")
	}

	// Should have 1 artifact
	if len(result.Artifacts) != 1 {
		t.Errorf("Execute() len(Artifacts) = %d, want 1", len(result.Artifacts))
	}

	if len(result.Artifacts) > 0 {
		artifact := result.Artifacts[0]
		if artifact.Type != attacks.ArtifactFile {
			t.Errorf("Artifact type = %v, want %v", artifact.Type, attacks.ArtifactFile)
		}
		if artifact.Identifier != "deploy_key_12345" {
			t.Errorf("Artifact identifier = %q, want %q", artifact.Identifier, "deploy_key_12345")
		}
	}

	// CRITICAL: CleanupActions should be set in real mode
	if len(result.CleanupActions) != 1 {
		t.Errorf("Execute() len(CleanupActions) = %d, want 1", len(result.CleanupActions))
	}

	if len(result.CleanupActions) > 0 {
		cleanup := result.CleanupActions[0]
		if cleanup.Type != attacks.ArtifactFile {
			t.Errorf("Cleanup type = %v, want %v", cleanup.Type, attacks.ArtifactFile)
		}
		if cleanup.Identifier != "12345" {
			t.Errorf("Cleanup identifier = %q, want %q", cleanup.Identifier, "12345")
		}
		if cleanup.Action != "delete" {
			t.Errorf("Cleanup action = %q, want %q", cleanup.Action, "delete")
		}
	}
}

func TestExecute_RealMode_MaliciousWorkflow(t *testing.T) {
	plugin := New()

	// Create mock server with comprehensive API responses
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch {
		case r.URL.Path == "/repos/owner/repo":
			// Repository info
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"default_branch": "main", "owner": {"login": "owner"}, "name": "repo"}`))
		case r.URL.Path == "/repos/owner/repo/git/refs/heads/main":
			// Default branch SHA
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"object": {"sha": "abc123def456"}}`))
		case r.URL.Path == "/repos/owner/repo/git/refs" && r.Method == "POST":
			// Branch creation
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte(`{"ref": "refs/heads/trajan-persist-test-session", "object": {"sha": "abc123def456"}}`))
		case r.URL.Path == "/repos/owner/repo/contents/.github/workflows/ci-lint.yml" && r.Method == "PUT":
			// Workflow file creation
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte(`{"content": {"name": "ci-lint.yml", "path": ".github/workflows/ci-lint.yml"}}`))
		case r.URL.Path == "/repos/owner/repo/pulls" && r.Method == "POST":
			// PR creation
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte(`{"id": 789, "number": 42, "html_url": "https://github.com/owner/repo/pull/42"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	platform := github.NewPlatform()
	ctx := context.Background()
	if err := platform.Init(ctx, platforms.Config{
		Token:   "test-token",
		BaseURL: server.URL,
	}); err != nil {
		t.Fatalf("Failed to init platform: %v", err)
	}

	opts := attacks.AttackOptions{
		Target:    platforms.Target{Type: platforms.TargetRepo, Value: "owner/repo"},
		Platform:  platform,
		DryRun:    false, // IMPORTANT: Not dry-run
		SessionID: "test-session",
		ExtraOpts: map[string]string{
			"method": "malicious_workflow",
			"c2_url": "https://test.example.com/callback",
		},
	}

	result, err := plugin.Execute(ctx, opts)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	if !result.Success {
		t.Errorf("Execute() Success = %v, want true", result.Success)
	}

	// Should have 3 artifacts: branch, workflow, PR
	if len(result.Artifacts) != 3 {
		t.Errorf("Execute() len(Artifacts) = %d, want 3", len(result.Artifacts))
	}

	// Verify artifact types
	expectedTypes := map[attacks.ArtifactType]int{
		attacks.ArtifactBranch:   0,
		attacks.ArtifactWorkflow: 0,
		attacks.ArtifactPR:       0,
	}

	for _, artifact := range result.Artifacts {
		if _, ok := expectedTypes[artifact.Type]; ok {
			expectedTypes[artifact.Type]++
		} else {
			t.Errorf("Unexpected artifact type: %v", artifact.Type)
		}
	}

	for typ, count := range expectedTypes {
		if count != 1 {
			t.Errorf("Expected 1 artifact of type %v, got %d", typ, count)
		}
	}

	// CRITICAL: CleanupActions should be set in real mode (PR + branch)
	if len(result.CleanupActions) != 2 {
		t.Errorf("Execute() len(CleanupActions) = %d, want 2", len(result.CleanupActions))
	}
}

func TestExecute_RealMode_Collaborator(t *testing.T) {
	plugin := New()

	// Create mock server with comprehensive API responses
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch {
		case r.URL.Path == "/repos/owner/repo":
			// Repository info
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"default_branch": "main", "owner": {"login": "owner"}, "name": "repo"}`))
		case r.URL.Path == "/repos/owner/repo/collaborators/testuser" && r.Method == "PUT":
			// Collaborator invitation
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte(`{"login": "testuser", "permissions": {"admin": true, "push": true, "pull": true}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	platform := github.NewPlatform()
	ctx := context.Background()
	if err := platform.Init(ctx, platforms.Config{
		Token:   "test-token",
		BaseURL: server.URL,
	}); err != nil {
		t.Fatalf("Failed to init platform: %v", err)
	}

	opts := attacks.AttackOptions{
		Target:    platforms.Target{Type: platforms.TargetRepo, Value: "owner/repo"},
		Platform:  platform,
		DryRun:    false, // IMPORTANT: Not dry-run
		SessionID: "test-session",
		ExtraOpts: map[string]string{
			"method":     "collaborator",
			"username":   "testuser",
			"permission": "admin",
		},
	}

	result, err := plugin.Execute(ctx, opts)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	if !result.Success {
		t.Errorf("Execute() Success = %v, want true", result.Success)
	}

	expectedMsg := "Invited testuser as collaborator with admin permission"
	if result.Message != expectedMsg {
		t.Errorf("Execute() Message = %q, want %q", result.Message, expectedMsg)
	}

	// Should have 1 artifact
	if len(result.Artifacts) != 1 {
		t.Errorf("Execute() len(Artifacts) = %d, want 1", len(result.Artifacts))
	}

	if len(result.Artifacts) > 0 {
		artifact := result.Artifacts[0]
		if artifact.Type != attacks.ArtifactFile {
			t.Errorf("Artifact type = %v, want %v", artifact.Type, attacks.ArtifactFile)
		}
		if artifact.Identifier != "testuser" {
			t.Errorf("Artifact identifier = %q, want %q", artifact.Identifier, "testuser")
		}
	}

	// CRITICAL: CleanupActions should be set in real mode
	if len(result.CleanupActions) != 1 {
		t.Errorf("Execute() len(CleanupActions) = %d, want 1", len(result.CleanupActions))
	}

	if len(result.CleanupActions) > 0 {
		cleanup := result.CleanupActions[0]
		if cleanup.Type != attacks.ArtifactFile {
			t.Errorf("Cleanup type = %v, want %v", cleanup.Type, attacks.ArtifactFile)
		}
		if cleanup.Identifier != "testuser" {
			t.Errorf("Cleanup identifier = %q, want %q", cleanup.Identifier, "testuser")
		}
		if cleanup.Action != "delete" {
			t.Errorf("Cleanup action = %q, want %q", cleanup.Action, "delete")
		}
	}
}

func TestCleanup_DeployKey(t *testing.T) {
	plugin := New()

	// Track API calls
	var deleteKeyCalledWith int64

	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch {
		case r.URL.Path == "/repos/owner/repo/keys/12345" && r.Method == "DELETE":
			// Deploy key deletion
			deleteKeyCalledWith = 12345
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	platform := github.NewPlatform()
	ctx := context.Background()
	if err := platform.Init(ctx, platforms.Config{
		Token:   "test-token",
		BaseURL: server.URL,
	}); err != nil {
		t.Fatalf("Failed to init platform: %v", err)
	}

	// Create a session with a deploy key cleanup action
	session := &attacks.Session{
		Platform: platform,
		Target:   platforms.Target{Type: platforms.TargetRepo, Value: "owner/repo"},
		Results: []*attacks.AttackResult{
			{
				Plugin: "persistence",
				CleanupActions: []attacks.CleanupAction{
					{
						Type:        attacks.ArtifactFile,
						Identifier:  "12345", // Deploy key ID
						Action:      "delete",
						Description: "Remove deploy key",
					},
				},
			},
		},
	}

	// Execute cleanup
	err := plugin.Cleanup(ctx, session)
	if err != nil {
		t.Fatalf("Cleanup() error = %v", err)
	}

	// Verify the delete API was called with correct key ID
	if deleteKeyCalledWith != 12345 {
		t.Errorf("DeleteDeployKey called with ID %d, want 12345", deleteKeyCalledWith)
	}
}

func TestCleanup_CollaboratorWithDigitPrefix(t *testing.T) {
	plugin := New()

	// Track API calls to verify correct behavior
	var deleteKeyCalledWith int64
	var removeCollaboratorCalledWith string

	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch {
		case r.URL.Path == "/repos/owner/repo/keys/123" && r.Method == "DELETE":
			// Deploy key deletion (should be called for "123")
			deleteKeyCalledWith = 123
			w.WriteHeader(http.StatusNoContent)
		case r.URL.Path == "/repos/owner/repo/collaborators/123user" && r.Method == "DELETE":
			// Collaborator removal (should be called for "123user")
			removeCollaboratorCalledWith = "123user"
			w.WriteHeader(http.StatusNoContent)
		case r.URL.Path == "/repos/owner/repo/collaborators/normaluser" && r.Method == "DELETE":
			// Collaborator removal (should be called for "normaluser")
			removeCollaboratorCalledWith = "normaluser"
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	platform := github.NewPlatform()
	ctx := context.Background()
	if err := platform.Init(ctx, platforms.Config{
		Token:   "test-token",
		BaseURL: server.URL,
	}); err != nil {
		t.Fatalf("Failed to init platform: %v", err)
	}

	tests := []struct {
		name                       string
		identifier                 string
		wantDeleteKeyID            int64
		wantRemoveCollaboratorName string
	}{
		{
			name:            "pure numeric ID should delete deploy key",
			identifier:      "123",
			wantDeleteKeyID: 123,
		},
		{
			name:                       "username starting with digits should remove collaborator",
			identifier:                 "123user",
			wantRemoveCollaboratorName: "123user",
		},
		{
			name:                       "normal username should remove collaborator",
			identifier:                 "normaluser",
			wantRemoveCollaboratorName: "normaluser",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset tracking variables
			deleteKeyCalledWith = 0
			removeCollaboratorCalledWith = ""

			// Create a session with a cleanup action
			session := &attacks.Session{
				Platform: platform,
				Target:   platforms.Target{Type: platforms.TargetRepo, Value: "owner/repo"},
				Results: []*attacks.AttackResult{
					{
						Plugin: "persistence",
						CleanupActions: []attacks.CleanupAction{
							{
								Type:        attacks.ArtifactFile,
								Identifier:  tt.identifier,
								Action:      "delete",
								Description: "Test cleanup",
							},
						},
					},
				},
			}

			// Execute cleanup
			err := plugin.Cleanup(ctx, session)
			if err != nil {
				t.Fatalf("Cleanup() error = %v", err)
			}

			// Verify correct API was called
			if tt.wantDeleteKeyID != 0 {
				if deleteKeyCalledWith != tt.wantDeleteKeyID {
					t.Errorf("DeleteDeployKey called with ID %d, want %d", deleteKeyCalledWith, tt.wantDeleteKeyID)
				}
				if removeCollaboratorCalledWith != "" {
					t.Errorf("RemoveCollaborator should not be called, but was called with %q", removeCollaboratorCalledWith)
				}
			}

			if tt.wantRemoveCollaboratorName != "" {
				if removeCollaboratorCalledWith != tt.wantRemoveCollaboratorName {
					t.Errorf("RemoveCollaborator called with %q, want %q", removeCollaboratorCalledWith, tt.wantRemoveCollaboratorName)
				}
				if deleteKeyCalledWith != 0 {
					t.Errorf("DeleteDeployKey should not be called, but was called with ID %d", deleteKeyCalledWith)
				}
			}
		})
	}
}

type invalidPlatform struct{}

func (i *invalidPlatform) Name() string {
	return "invalid"
}

func (i *invalidPlatform) Init(ctx context.Context, config platforms.Config) error {
	return nil
}

func (i *invalidPlatform) Scan(ctx context.Context, target platforms.Target) (*platforms.ScanResult, error) {
	return nil, nil
}
