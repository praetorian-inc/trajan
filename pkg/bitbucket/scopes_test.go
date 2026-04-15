package bitbucket

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseScopes_Legacy(t *testing.T) {
	tests := []struct {
		name     string
		header   string
		wantCaps map[string][]ScopeLevel
		notCaps  map[string][]ScopeLevel
	}{
		{
			name:   "single scope repository read",
			header: "repository",
			wantCaps: map[string][]ScopeLevel{
				"repository": {ScopeLevelRead},
			},
			notCaps: map[string][]ScopeLevel{
				"repository": {ScopeLevelWrite, ScopeLevelAdmin},
			},
		},
		{
			name:   "pullrequest:write implies pullrequest and repository read+write",
			header: "pullrequest:write",
			wantCaps: map[string][]ScopeLevel{
				"pullrequest": {ScopeLevelWrite, ScopeLevelRead},
				"repository":  {ScopeLevelWrite, ScopeLevelRead},
			},
		},
		{
			name:   "repository:admin is standalone - does NOT imply read",
			header: "repository:admin",
			wantCaps: map[string][]ScopeLevel{
				"repository": {ScopeLevelAdmin},
			},
			notCaps: map[string][]ScopeLevel{
				"repository": {ScopeLevelRead, ScopeLevelWrite},
			},
		},
		{
			name:   "project:admin is standalone - does NOT imply project read",
			header: "project:admin",
			wantCaps: map[string][]ScopeLevel{
				"project": {ScopeLevelAdmin},
			},
			notCaps: map[string][]ScopeLevel{
				"project":    {ScopeLevelRead},
				"repository": {ScopeLevelRead},
			},
		},
		{
			name:   "repository:delete is standalone",
			header: "repository:delete",
			wantCaps: map[string][]ScopeLevel{
				"repository": {ScopeLevelDelete},
			},
			notCaps: map[string][]ScopeLevel{
				"repository": {ScopeLevelRead, ScopeLevelWrite},
			},
		},
		{
			name:   "multiple scopes combined",
			header: "repository:admin, repository:write, pipeline:variable",
			wantCaps: map[string][]ScopeLevel{
				"repository": {ScopeLevelAdmin, ScopeLevelWrite, ScopeLevelRead},
				"pipeline":   {ScopeLevelVariable, ScopeLevelWrite, ScopeLevelRead},
			},
		},
		{
			name:   "pipeline:variable transitive - has variable, write, and read",
			header: "pipeline:variable",
			wantCaps: map[string][]ScopeLevel{
				"pipeline": {ScopeLevelVariable, ScopeLevelWrite, ScopeLevelRead},
			},
		},
		{
			name:   "project implies project read and repository read",
			header: "project",
			wantCaps: map[string][]ScopeLevel{
				"project":    {ScopeLevelRead},
				"repository": {ScopeLevelRead},
			},
		},
		{
			name:     "empty string",
			header:   "",
			wantCaps: nil,
		},
		{
			name:   "comma-only separation (no spaces)",
			header: "repository:admin,repository:write,pipeline",
			wantCaps: map[string][]ScopeLevel{
				"repository": {ScopeLevelAdmin, ScopeLevelWrite, ScopeLevelRead},
				"pipeline":   {ScopeLevelRead},
			},
		},
		{
			name:   "unknown scopes are silently dropped",
			header: "repository,unknown_scope,pipeline",
			wantCaps: map[string][]ScopeLevel{
				"repository": {ScopeLevelRead},
				"pipeline":   {ScopeLevelRead},
			},
			notCaps: map[string][]ScopeLevel{
				"unknown_scope": {ScopeLevelRead},
			},
		},
		{
			name:   "webhook grants both read and write",
			header: "webhook",
			wantCaps: map[string][]ScopeLevel{
				"webhook": {ScopeLevelRead, ScopeLevelWrite},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := ParseScopes(tt.header, ScopeFormatLegacy)
			require.NotNil(t, s)
			assert.Equal(t, ScopeFormatLegacy, s.Format())
			assert.Equal(t, tt.header, s.Raw())

			for category, levels := range tt.wantCaps {
				for _, level := range levels {
					assert.True(t, s.HasCapability(category, level),
						"expected %s:%s to be present", category, level)
				}
			}

			for category, levels := range tt.notCaps {
				for _, level := range levels {
					assert.False(t, s.HasCapability(category, level),
						"expected %s:%s to NOT be present", category, level)
				}
			}
		})
	}
}

func TestParseScopes_FineGrained(t *testing.T) {
	tests := []struct {
		name     string
		header   string
		wantCaps map[string][]ScopeLevel
		notCaps  map[string][]ScopeLevel
	}{
		{
			name:   "single fine-grained scope",
			header: "read:repository:bitbucket",
			wantCaps: map[string][]ScopeLevel{
				"repository": {ScopeLevelRead},
			},
			notCaps: map[string][]ScopeLevel{
				"repository": {ScopeLevelWrite},
			},
		},
		{
			name:   "multiple fine-grained scopes",
			header: "read:repository:bitbucket, write:repository:bitbucket",
			wantCaps: map[string][]ScopeLevel{
				"repository": {ScopeLevelRead, ScopeLevelWrite},
			},
		},
		{
			name:     "empty string",
			header:   "",
			wantCaps: nil,
		},
		{
			name:   "malformed scopes with only 2 parts are dropped",
			header: "read:repository,write:pipeline:bitbucket",
			wantCaps: map[string][]ScopeLevel{
				"pipeline": {ScopeLevelWrite},
			},
			notCaps: map[string][]ScopeLevel{
				"repository": {ScopeLevelRead},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := ParseScopes(tt.header, ScopeFormatFineGrained)
			require.NotNil(t, s)
			assert.Equal(t, ScopeFormatFineGrained, s.Format())
			assert.Equal(t, tt.header, s.Raw())

			for category, levels := range tt.wantCaps {
				for _, level := range levels {
					assert.True(t, s.HasCapability(category, level),
						"expected %s:%s to be present", category, level)
				}
			}

			for category, levels := range tt.notCaps {
				for _, level := range levels {
					assert.False(t, s.HasCapability(category, level),
						"expected %s:%s to NOT be present", category, level)
				}
			}
		})
	}
}

func TestScopes_HasCapability_NonExistent(t *testing.T) {
	s := ParseScopes("repository", ScopeFormatLegacy)

	assert.False(t, s.HasCapability("nonexistent", ScopeLevelRead),
		"non-existent category should return false")
	assert.False(t, s.HasCapability("repository", ScopeLevelAdmin),
		"non-existent level should return false")
}

func TestScopes_HasCapability_Nil(t *testing.T) {
	var s *Scopes
	assert.False(t, s.HasCapability("repository", ScopeLevelRead))
}

func TestScopes_Categories(t *testing.T) {
	s := ParseScopes("pullrequest:write, pipeline:variable", ScopeFormatLegacy)
	cats := s.Categories()

	assert.Equal(t, []string{"pipeline", "pullrequest", "repository"}, cats,
		"categories should be sorted and include implied categories")
}

func TestScopes_Categories_Empty(t *testing.T) {
	s := ParseScopes("", ScopeFormatLegacy)
	assert.Empty(t, s.Categories())
}

func TestScopes_Categories_Nil(t *testing.T) {
	var s *Scopes
	assert.Nil(t, s.Categories())
}

func TestScopes_Levels(t *testing.T) {
	s := ParseScopes("pipeline:variable", ScopeFormatLegacy)
	levels := s.Levels("pipeline")

	assert.Len(t, levels, 3)
	assert.Contains(t, levels, ScopeLevelVariable)
	assert.Contains(t, levels, ScopeLevelWrite)
	assert.Contains(t, levels, ScopeLevelRead)
}

func TestScopes_Levels_NonExistent(t *testing.T) {
	s := ParseScopes("repository", ScopeFormatLegacy)
	assert.Nil(t, s.Levels("nonexistent"))
}

func TestScopes_Raw_Nil(t *testing.T) {
	var s *Scopes
	assert.Equal(t, "", s.Raw())
}

func TestScopes_Format_Nil(t *testing.T) {
	var s *Scopes
	assert.Equal(t, ScopeFormat(""), s.Format())
}
