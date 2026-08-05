package bitbucket

import (
	"sort"
	"strings"
)

type ScopeFormat string

const (
	// Access-token format, e.g. "repository:admin".
	ScopeFormatLegacy ScopeFormat = "legacy"
	// API-token format, e.g. "read:repository:bitbucket".
	ScopeFormatFineGrained ScopeFormat = "fine_grained"
)

type ScopeLevel string

const (
	ScopeLevelRead     ScopeLevel = "read"
	ScopeLevelWrite    ScopeLevel = "write"
	ScopeLevelAdmin    ScopeLevel = "admin"
	ScopeLevelDelete   ScopeLevel = "delete"
	ScopeLevelVariable ScopeLevel = "variable"
)

type Scopes struct {
	raw          string
	format       ScopeFormat
	capabilities map[string]map[ScopeLevel]bool
}

type scopeEntry struct {
	category string
	level    ScopeLevel
}

// Transitive closure: the x-oauth-scopes header reports only the highest granted
// level, so each scope must expand to every capability it implies.
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
	"webhook":        {{category: "webhook", level: ScopeLevelRead}, {category: "webhook", level: ScopeLevelWrite}},
	"pipeline":       {{category: "pipeline", level: ScopeLevelRead}},
	"pipeline:write": {{category: "pipeline", level: ScopeLevelWrite}, {category: "pipeline", level: ScopeLevelRead}},
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

// Scopes are "{action}:{resource}:bitbucket" and imply nothing further.
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

func (s *Scopes) addCapability(category string, level ScopeLevel) {
	if s.capabilities[category] == nil {
		s.capabilities[category] = make(map[ScopeLevel]bool)
	}
	s.capabilities[category][level] = true
}

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

func (s *Scopes) Raw() string {
	if s == nil {
		return ""
	}
	return s.raw
}

func (s *Scopes) Format() ScopeFormat {
	if s == nil {
		return ""
	}
	return s.format
}
