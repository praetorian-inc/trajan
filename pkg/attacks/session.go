package attacks

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/praetorian-inc/trajan/pkg/platforms"
)

// Session tracks attack execution for cleanup
type Session struct {
	ID           string             `json:"id"`
	PlatformName string             `json:"platform"`      // NEW: store platform for cleanup
	Org          string             `json:"org,omitempty"` // NEW: store org for cleanup (ADO needs it)
	Target       platforms.Target   `json:"target"`
	CreatedAt    time.Time          `json:"created_at"`
	Results      []*AttackResult    `json:"results"`
	Platform     platforms.Platform `json:"-"` // Not serialized, set during cleanup
}

// SessionSummary for listing sessions
type SessionSummary struct {
	ID            string           `json:"id"`
	PlatformName  string           `json:"platform"`
	Target        platforms.Target `json:"target"`
	CreatedAt     time.Time        `json:"created_at"`
	ArtifactCount int              `json:"artifact_count"`
}

// NewSession creates a new attack session
func NewSession(id string, target platforms.Target, platformName, org string) *Session {
	return &Session{
		ID:           id,
		PlatformName: platformName,
		Org:          org,
		Target:       target,
		CreatedAt:    time.Now(),
		Results:      make([]*AttackResult, 0),
	}
}

// AddResult adds an attack result to the session
func (s *Session) AddResult(result *AttackResult) {
	s.Results = append(s.Results, result)
}

// sessionsDir returns the directory for session files
func sessionsDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".trajan/sessions"
	}
	return filepath.Join(home, ".trajan", "sessions")
}

// sessionPath returns the file path for a session
func sessionPath(id string) string {
	return filepath.Join(sessionsDir(), id+".json")
}

// Save persists the session to disk
func (s *Session) Save() error {
	dir := sessionsDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("creating sessions directory: %w", err)
	}

	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling session: %w", err)
	}

	path := sessionPath(s.ID)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("writing session file: %w", err)
	}

	return nil
}

// Delete removes the session file
func (s *Session) Delete() error {
	return os.Remove(sessionPath(s.ID))
}

// LoadSession loads a session from disk
func LoadSession(id string) (*Session, error) {
	data, err := os.ReadFile(sessionPath(id))
	if err != nil {
		return nil, fmt.Errorf("reading session file: %w", err)
	}

	var session Session
	if err := json.Unmarshal(data, &session); err != nil {
		return nil, fmt.Errorf("unmarshaling session: %w", err)
	}

	return &session, nil
}

// ListSessions returns all available sessions
func ListSessions() ([]SessionSummary, error) {
	dir := sessionsDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading sessions directory: %w", err)
	}

	var summaries []SessionSummary
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}

		id := entry.Name()[:len(entry.Name())-5] // Remove .json
		session, err := LoadSession(id)
		if err != nil {
			continue
		}

		artifactCount := 0
		for _, r := range session.Results {
			artifactCount += len(r.Artifacts)
		}

		summaries = append(summaries, SessionSummary{
			ID:            session.ID,
			PlatformName:  session.PlatformName,
			Target:        session.Target,
			CreatedAt:     session.CreatedAt,
			ArtifactCount: artifactCount,
		})
	}

	return summaries, nil
}
