package bitbucket

import (
	"sort"
	"strings"
)

// ScopeFormat distinguishes between the two Bitbucket scope systems.
type ScopeFormat string

const (
	// ScopeFormatLegacy is the access token scope format (e.g., "repository:admin").
	ScopeFormatLegacy ScopeFormat = "legacy"
	// ScopeFormatFineGrained is the API token scope format (e.g., "read:repository:bitbucket").
	ScopeFormatFineGrained ScopeFormat = "fine_grained"
)

// ScopeLevel represents the permission level within a scope category.
type ScopeLevel string

const (
	ScopeLevelRead     ScopeLevel = "read"
	ScopeLevelWrite    ScopeLevel = "write"
	ScopeLevelAdmin    ScopeLevel = "admin"
	ScopeLevelDelete   ScopeLevel = "delete"
	ScopeLevelVariable ScopeLevel = "variable"
)

// Scopes represents parsed OAuth scopes from a Bitbucket token.
type Scopes struct {
	raw          string
	format       ScopeFormat
	capabilities map[string]map[ScopeLevel]bool
}

// scopeEntry pairs a category with a level for the implication table.
type scopeEntry struct {
	category string
	level    ScopeLevel
}

// legacyImplications is a pre-computed transitive closure of scope implications.
// Each key maps to ALL capabilities it grants, including transitive ones.
// The x-oauth-scopes header only reports the highest granted level, so the
// parser must expand each scope to its full set of implied capabilities.
var legacyImplications = map[string][]scopeEntry{
	"project":           {{category: "project", level: ScopeLevelRead}, {category: "repository", level: ScopeLevelRead}},
	"project:admin":     {{category: "project", level: ScopeLevelAdmin}},
	"repository":        {{category: "repository", level: ScopeLevelRead}},
	"repository:write":  {{category: "repository", level: ScopeLevelWrite}, {category: "repository", level: ScopeLevelRead}},
	"repository:admin":  {{category: "repository", level: ScopeLevelAdmin}},
	"repository:delete": {{category: "repository", level: ScopeLevelDelete}},
	"pullrequest":       {{category: "pullrequest", level: ScopeLevelRead}, {category: "repository", level: ScopeLevelRead}},
	"pullrequest:write": {
		{category: "pullrequest", level: ScopeLevelWrite}, {category: "pullrequest", level: ScopeLevelRead},
		{category: "repository", level: ScopeLevelWrite}, {category: "repository", level: ScopeLevelRead},
	},
	"webhook":           {{category: "webhook", level: ScopeLevelRead}, {category: "webhook", level: ScopeLevelWrite}},
	"pipeline":          {{category: "pipeline", level: ScopeLevelRead}},
	"pipeline:write":    {{category: "pipeline", level: ScopeLevelWrite}, {category: "pipeline", level: ScopeLevelRead}},
	"pipeline:variable": {
		{category: "pipeline", level: ScopeLevelVariable},
		{category: "pipeline", level: ScopeLevelWrite},
		{category: "pipeline", level: ScopeLevelRead},
	},
	"runner":       {{category: "runner", level: ScopeLevelRead}},
	"runner:write": {{category: "runner", level: ScopeLevelWrite}, {category: "runner", level: ScopeLevelRead}},
	"test":         {{category: "test", level: ScopeLevelRead}},
	"test:write":   {{category: "test", level: ScopeLevelWrite}, {category: "test", level: ScopeLevelRead}},
	"account":      {{category: "account", level: ScopeLevelRead}},
}

// ParseScopes parses the x-oauth-scopes header value into a Scopes object.
// The format parameter determines how scope strings are interpreted.
func ParseScopes(header string, format ScopeFormat) *Scopes {
	s := &Scopes{
		raw:          header,
		format:       format,
		capabilities: make(map[string]map[ScopeLevel]bool),
	}

	if header == "" {
		return s
	}

	scopes := strings.Split(header, ",")

	switch format {
	case ScopeFormatLegacy:
		s.parseLegacy(scopes)
	case ScopeFormatFineGrained:
		s.parseFineGrained(scopes)
	}

	return s
}

// parseLegacy processes legacy-format scopes by expanding each through
// the implication graph.
func (s *Scopes) parseLegacy(scopes []string) {
	for _, scope := range scopes {
		scope = strings.TrimSpace(scope)
		if scope == "" {
			continue
		}
		entries, ok := legacyImplications[scope]
		if !ok {
			continue
		}
		for _, entry := range entries {
			s.addCapability(entry.category, entry.level)
		}
	}
}

// parseFineGrained processes fine-grained scopes in the format
// "{action}:{resource}:bitbucket". Each scope is independent with no implications.
func (s *Scopes) parseFineGrained(scopes []string) {
	for _, scope := range scopes {
		scope = strings.TrimSpace(scope)
		if scope == "" {
			continue
		}
		parts := strings.SplitN(scope, ":", 3)
		if len(parts) != 3 {
			continue
		}
		action := parts[0]
		resource := parts[1]
		s.addCapability(resource, ScopeLevel(action))
	}
}

// addCapability records a capability in the internal map.
func (s *Scopes) addCapability(category string, level ScopeLevel) {
	if s.capabilities[category] == nil {
		s.capabilities[category] = make(map[ScopeLevel]bool)
	}
	s.capabilities[category][level] = true
}

// HasCapability reports whether the token has a specific capability.
func (s *Scopes) HasCapability(category string, level ScopeLevel) bool {
	if s == nil || s.capabilities == nil {
		return false
	}
	levels, ok := s.capabilities[category]
	if !ok {
		return false
	}
	return levels[level]
}

// Categories returns a sorted list of all scope categories.
func (s *Scopes) Categories() []string {
	if s == nil || s.capabilities == nil {
		return nil
	}
	cats := make([]string, 0, len(s.capabilities))
	for cat := range s.capabilities {
		cats = append(cats, cat)
	}
	sort.Strings(cats)
	return cats
}

// Levels returns the permission levels granted for a specific category.
func (s *Scopes) Levels(category string) []ScopeLevel {
	if s == nil || s.capabilities == nil {
		return nil
	}
	levels, ok := s.capabilities[category]
	if !ok {
		return nil
	}
	result := make([]ScopeLevel, 0, len(levels))
	for level := range levels {
		result = append(result, level)
	}
	sort.Slice(result, func(i, j int) bool {
		return string(result[i]) < string(result[j])
	})
	return result
}

// Raw returns the original unparsed scope header value.
func (s *Scopes) Raw() string {
	if s == nil {
		return ""
	}
	return s.raw
}

// Format returns the scope format (legacy or fine-grained).
func (s *Scopes) Format() ScopeFormat {
	if s == nil {
		return ""
	}
	return s.format
}
