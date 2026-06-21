package gitlab

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/trajan/pkg/platforms"
)

func TestPlatform_EnumerateToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("RateLimit-Limit", "2000")
		w.Header().Set("RateLimit-Remaining", "1800")

		switch r.URL.Path {
		case "/api/v4/user":
			json.NewEncoder(w).Encode(User{
				ID:               1,
				Username:         "john_smith",
				Name:             "John Smith",
				Email:            "john@example.com",
				State:            "active",
				IsAdmin:          false,
				Bot:              false,
				CanCreateGroup:   true,
				CanCreateProject: true,
			})
		case "/api/v4/personal_access_tokens/self":
			json.NewEncoder(w).Encode(PersonalAccessToken{
				ID:        42,
				Name:      "CI Deploy Token",
				Active:    true,
				Scopes:    []string{"api", "read_user"},
				ExpiresAt: strPtr("2025-12-31"),
			})
		case "/api/v4/groups":
			json.NewEncoder(w).Encode([]Group{
				{ID: 10, Name: "my-company", FullPath: "my-company"},
				{ID: 11, Name: "backend", FullPath: "my-company/backend"},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	p := NewPlatform()
	err := p.Init(context.Background(), platforms.Config{
		Token:   "test-token",
		BaseURL: server.URL,
	})
	require.NoError(t, err)

	result, err := p.EnumerateToken(context.Background())
	require.NoError(t, err)

	// User info
	assert.Equal(t, "john_smith", result.User.Username)
	assert.Equal(t, "John Smith", result.User.Name)
	assert.False(t, result.IsAdmin)
	assert.False(t, result.IsBot)
	assert.True(t, result.CanCreateGroup)
	assert.True(t, result.CanCreateProject)

	// Token type detection: not bot + PAT succeeds = personal access token
	assert.Equal(t, "personal_access_token", result.TokenType)

	// Token info
	assert.Equal(t, "CI Deploy Token", result.Token.Name)
	assert.True(t, result.Token.Active)
	assert.Equal(t, []string{"api", "read_user"}, result.Token.Scopes)

	// Groups
	assert.Len(t, result.Groups, 2)
	assert.Equal(t, "my-company", result.Groups[0].Name)

	// Rate limit
	assert.NotNil(t, result.RateLimit)
	assert.Equal(t, 2000, result.RateLimit.Limit)

	// No errors
	assert.Empty(t, result.Errors)
}

func TestPlatform_EnumerateToken_BotProjectToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v4/user":
			json.NewEncoder(w).Encode(User{
				ID:       99,
				Username: "project_123_bot_abc",
				Bot:      true,
			})
		case "/api/v4/personal_access_tokens/self":
			// Project tokens may fail here
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"message":"404 Not Found"}`))
		case "/api/v4/groups":
			json.NewEncoder(w).Encode([]Group{})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	p := NewPlatform()
	err := p.Init(context.Background(), platforms.Config{Token: "test-token", BaseURL: server.URL})
	require.NoError(t, err)

	result, err := p.EnumerateToken(context.Background())
	require.NoError(t, err)

	assert.True(t, result.IsBot)
	assert.Equal(t, "project_access_token", result.TokenType)
}

func TestPlatform_EnumerateToken_BotGroupToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v4/user":
			json.NewEncoder(w).Encode(User{
				ID:       99,
				Username: "group_456_bot_xyz",
				Bot:      true,
			})
		case "/api/v4/personal_access_tokens/self":
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"message":"404 Not Found"}`))
		case "/api/v4/groups":
			json.NewEncoder(w).Encode([]Group{})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	p := NewPlatform()
	err := p.Init(context.Background(), platforms.Config{Token: "test-token", BaseURL: server.URL})
	require.NoError(t, err)

	result, err := p.EnumerateToken(context.Background())
	require.NoError(t, err)

	assert.True(t, result.IsBot)
	assert.Equal(t, "group_access_token", result.TokenType)
}

func TestPlatform_EnumerateProjects_Default(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch {
		case r.URL.Path == "/api/v4/projects" && r.URL.Query().Get("membership") == "true":
			json.NewEncoder(w).Encode([]Project{
				{
					ID: 1, Name: "api", Path: "api",
					PathWithNamespace: "company/api",
					DefaultBranch:     "main", Visibility: "private",
					WebURL:    "https://gitlab.com/company/api",
					Namespace: Namespace{Name: "company", FullPath: "company"},
					Permissions: &ProjectPermissions{
						ProjectAccess: &AccessInfo{AccessLevel: 40}, // Maintainer
					},
				},
				{
					ID: 2, Name: "docs", Path: "docs",
					PathWithNamespace: "company/docs",
					DefaultBranch:     "main", Visibility: "public",
					WebURL:    "https://gitlab.com/company/docs",
					Namespace: Namespace{Name: "company", FullPath: "company"},
					Permissions: &ProjectPermissions{
						GroupAccess: &AccessInfo{AccessLevel: 20}, // Reporter
					},
				},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	p := NewPlatform()
	err := p.Init(context.Background(), platforms.Config{Token: "test-token", BaseURL: server.URL})
	require.NoError(t, err)

	// Default: no target = member projects
	result, err := p.EnumerateProjects(context.Background(), platforms.Target{})
	require.NoError(t, err)

	assert.Len(t, result.Projects, 2)

	// First project: Maintainer (40)
	assert.Equal(t, "api", result.Projects[0].Name)
	assert.Equal(t, 40, result.Projects[0].AccessLevel)
	assert.Equal(t, "private", result.Projects[0].Visibility)

	// Second project: Reporter (20)
	assert.Equal(t, "docs", result.Projects[1].Name)
	assert.Equal(t, 20, result.Projects[1].AccessLevel)

	// Summary
	assert.Equal(t, 2, result.Summary.Total)
	assert.Equal(t, 1, result.Summary.Private)
	assert.Equal(t, 1, result.Summary.Public)
	assert.Equal(t, 1, result.Summary.WriteAccess) // Maintainer = write
	assert.Equal(t, 1, result.Summary.ReadAccess)  // Reporter = read
}

func TestPlatform_EnumerateProjects_GroupFilter(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/v4/groups/mygroup/projects" {
			json.NewEncoder(w).Encode([]Project{
				{
					ID: 1, Name: "proj1", Path: "proj1",
					PathWithNamespace: "mygroup/proj1",
					DefaultBranch:     "main", Visibility: "private",
					Namespace: Namespace{Name: "mygroup", FullPath: "mygroup"},
					Permissions: &ProjectPermissions{
						GroupAccess: &AccessInfo{AccessLevel: 50}, // Owner
					},
				},
			})
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	p := NewPlatform()
	err := p.Init(context.Background(), platforms.Config{Token: "test-token", BaseURL: server.URL})
	require.NoError(t, err)

	result, err := p.EnumerateProjects(context.Background(), platforms.Target{
		Type:  platforms.TargetOrg,
		Value: "mygroup",
	})
	require.NoError(t, err)

	assert.Len(t, result.Projects, 1)
	assert.Equal(t, "proj1", result.Projects[0].Name)
	assert.Equal(t, 50, result.Projects[0].AccessLevel)
}

func TestPlatform_EnumerateGroups_Basic(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/api/v4/user":
			json.NewEncoder(w).Encode(User{ID: 1, Username: "testuser"})

		case "/api/v4/groups":
			json.NewEncoder(w).Encode([]Group{
				{ID: 10, Name: "company", FullPath: "company", Visibility: "private"},
				{ID: 11, Name: "infra", FullPath: "company/infra", Visibility: "private", ParentID: intPtr(10)},
			})

		case "/api/v4/groups/10/members/1":
			json.NewEncoder(w).Encode(Member{ID: 1, AccessLevel: 50}) // Owner

		case "/api/v4/groups/11/members/1":
			json.NewEncoder(w).Encode(Member{ID: 1, AccessLevel: 40}) // Maintainer

		case "/api/v4/groups/10/groups/shared":
			json.NewEncoder(w).Encode([]SharedGroup{
				{ID: 20, Name: "partner-tools", FullPath: "partner/tools", GroupAccessLevel: 30},
			})

		case "/api/v4/groups/11/groups/shared":
			json.NewEncoder(w).Encode([]SharedGroup{})

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	p := NewPlatform()
	err := p.Init(context.Background(), platforms.Config{Token: "test-token", BaseURL: server.URL})
	require.NoError(t, err)

	result, err := p.EnumerateGroups(context.Background(), false)
	require.NoError(t, err)

	// With recursive=false: 1 top-level group + 1 shared group = 2 total
	// (infra is filtered out because it has ParentID=10)
	assert.Len(t, result.Groups, 2)

	// Check top-level group
	assert.Equal(t, "company", result.Groups[0].Name)
	assert.Equal(t, 50, result.Groups[0].AccessLevel)
	assert.False(t, result.Groups[0].Shared)

	// Check shared group
	assert.Equal(t, "partner-tools", result.Groups[1].Name)
	assert.True(t, result.Groups[1].Shared)
	assert.Equal(t, "company", result.Groups[1].SharedVia)
}

func TestPlatform_EnumerateGroups_Recursive(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch {
		case r.URL.Path == "/api/v4/user":
			json.NewEncoder(w).Encode(User{ID: 1, Username: "testuser"})

		case r.URL.Path == "/api/v4/groups" && r.URL.Query().Get("page") != "2":
			json.NewEncoder(w).Encode([]Group{
				{ID: 10, Name: "company", FullPath: "company", Visibility: "private"},
			})

		case r.URL.Path == "/api/v4/groups/10/subgroups":
			json.NewEncoder(w).Encode([]Group{
				{ID: 11, Name: "infra", FullPath: "company/infra", ParentID: intPtr(10)},
			})

		case r.URL.Path == "/api/v4/groups/11/subgroups":
			json.NewEncoder(w).Encode([]Group{}) // No deeper subgroups

		case r.URL.Path == "/api/v4/groups/10/members/1":
			json.NewEncoder(w).Encode(Member{ID: 1, AccessLevel: 50})

		case r.URL.Path == "/api/v4/groups/11/members/1":
			json.NewEncoder(w).Encode(Member{ID: 1, AccessLevel: 30})

		case strings.HasSuffix(r.URL.Path, "/groups/shared"):
			json.NewEncoder(w).Encode([]SharedGroup{})

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	p := NewPlatform()
	err := p.Init(context.Background(), platforms.Config{Token: "test-token", BaseURL: server.URL})
	require.NoError(t, err)

	result, err := p.EnumerateGroups(context.Background(), true)
	require.NoError(t, err)

	// Should have both the top-level group and the recursively discovered subgroup
	assert.Len(t, result.Groups, 2)
	assert.Equal(t, "company", result.Groups[0].Name)
	assert.Equal(t, "infra", result.Groups[1].Name)
}

func TestPlatform_EnumerateSecrets_Project(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/api/v4/projects/company/api":
			json.NewEncoder(w).Encode(Project{
				ID: 1, Name: "api", PathWithNamespace: "company/api",
				Namespace: Namespace{FullPath: "company"},
			})

		case "/api/v4/projects/1/variables":
			json.NewEncoder(w).Encode([]Variable{
				{Key: "DATABASE_URL", Value: "postgres://...", VariableType: "env_var", Masked: true, EnvironmentScope: "*"},
				{Key: "DEPLOY_KEY", Value: "-----BEGIN", VariableType: "file", Protected: true, EnvironmentScope: "production"},
			})

		case "/api/v4/admin/ci/variables":
			// Not admin
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"message":"403 Forbidden"}`))

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	p := NewPlatform()
	err := p.Init(context.Background(), platforms.Config{Token: "test-token", BaseURL: server.URL})
	require.NoError(t, err)

	result, err := p.EnumerateSecrets(context.Background(), platforms.Target{
		Type:  platforms.TargetRepo,
		Value: "company/api",
	})
	require.NoError(t, err)

	// Project variables
	assert.Len(t, result.ProjectVariables["company/api"], 2)
	assert.Equal(t, "DATABASE_URL", result.ProjectVariables["company/api"][0].Key)

	// Instance variables failed (not admin) - 403 is silently ignored
	assert.Empty(t, result.InstanceVariables)
	assert.Empty(t, result.PermissionErrors) // 403 not shown as error
}

func TestPlatform_EnumerateSecrets_Group(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/api/v4/groups/company":
			json.NewEncoder(w).Encode(Group{ID: 10, Name: "company", FullPath: "company"})

		case "/api/v4/groups/10/variables":
			json.NewEncoder(w).Encode([]Variable{
				{Key: "AWS_ACCESS_KEY_ID", Value: "AKIA...", VariableType: "env_var", Masked: true},
			})

		case "/api/v4/groups/company/projects":
			json.NewEncoder(w).Encode([]Project{
				{ID: 1, Name: "api", PathWithNamespace: "company/api"},
				{ID: 2, Name: "web", PathWithNamespace: "company/web"},
			})

		case "/api/v4/projects/1/variables":
			json.NewEncoder(w).Encode([]Variable{
				{Key: "DB_PASSWORD", Value: "secret", VariableType: "env_var"},
			})

		case "/api/v4/projects/2/variables":
			json.NewEncoder(w).Encode([]Variable{})

		case "/api/v4/admin/ci/variables":
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"message":"403 Forbidden"}`))

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	p := NewPlatform()
	err := p.Init(context.Background(), platforms.Config{Token: "test-token", BaseURL: server.URL})
	require.NoError(t, err)

	result, err := p.EnumerateSecrets(context.Background(), platforms.Target{
		Type:  platforms.TargetOrg,
		Value: "company",
	})
	require.NoError(t, err)

	// Group variables
	assert.Len(t, result.GroupVariables["company"], 1)
	assert.Equal(t, "AWS_ACCESS_KEY_ID", result.GroupVariables["company"][0].Key)

	// Project variables (from group's projects)
	assert.Len(t, result.ProjectVariables["company/api"], 1)
	assert.Empty(t, result.ProjectVariables["company/web"])
}

func TestPlatform_EnumerateSecrets_NoTarget(t *testing.T) {
	p := NewPlatform()
	err := p.Init(context.Background(), platforms.Config{Token: "test-token", BaseURL: "http://unused"})
	require.NoError(t, err)

	result, err := p.EnumerateSecrets(context.Background(), platforms.Target{})
	require.NoError(t, err)
	assert.NotEmpty(t, result.Errors)
	assert.Contains(t, result.Errors[0], "must specify")
}

func TestPlatform_EnumerateToken_PartialFailure(t *testing.T) {
	// Token info fails but user and groups succeed
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v4/user":
			json.NewEncoder(w).Encode(User{ID: 1, Username: "test"})
		case "/api/v4/personal_access_tokens/self":
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"message":"not found"}`))
		case "/api/v4/groups":
			json.NewEncoder(w).Encode([]Group{{ID: 1, Name: "g1"}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	p := NewPlatform()
	err := p.Init(context.Background(), platforms.Config{Token: "test-token", BaseURL: server.URL})
	require.NoError(t, err)

	result, err := p.EnumerateToken(context.Background())
	require.NoError(t, err)

	// User info present
	assert.Equal(t, "test", result.User.Username)
	// Token info missing
	assert.Nil(t, result.Token)
	// Groups present
	assert.Len(t, result.Groups, 1)
	// Has error about token info
	assert.NotEmpty(t, result.Errors)
}

func TestGetEffectiveAccessLevel(t *testing.T) {
	tests := []struct {
		name     string
		perms    *ProjectPermissions
		expected int
	}{
		{"nil permissions", nil, 0},
		{"project access only", &ProjectPermissions{ProjectAccess: &AccessInfo{AccessLevel: 30}}, 30},
		{"group access only", &ProjectPermissions{GroupAccess: &AccessInfo{AccessLevel: 40}}, 40},
		{"both - project higher", &ProjectPermissions{
			ProjectAccess: &AccessInfo{AccessLevel: 50},
			GroupAccess:   &AccessInfo{AccessLevel: 30},
		}, 50},
		{"both - group higher", &ProjectPermissions{
			ProjectAccess: &AccessInfo{AccessLevel: 20},
			GroupAccess:   &AccessInfo{AccessLevel: 40},
		}, 40},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, getEffectiveAccessLevel(tt.perms))
		})
	}
}

func TestDetectTokenType(t *testing.T) {
	tests := []struct {
		name     string
		user     *User
		pat      *PersonalAccessToken
		expected string
	}{
		{"nil user", nil, nil, "unknown"},
		{"personal access token", &User{Bot: false}, &PersonalAccessToken{ID: 1}, "personal_access_token"},
		{"project bot token", &User{Bot: true, Username: "project_123_bot_abc"}, nil, "project_access_token"},
		{"group bot token", &User{Bot: true, Username: "group_456_bot_xyz"}, nil, "group_access_token"},
		{"unknown bot", &User{Bot: true, Username: "other_bot"}, nil, "bot_token"},
		{"no pat, not bot", &User{Bot: false}, nil, "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, detectTokenType(tt.user, tt.pat))
		})
	}
}

func strPtr(s string) *string { return &s }
func intPtr(i int) *int       { return &i }
