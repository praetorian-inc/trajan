package storage

import (
	"context"
	"time"
)

type Storage interface {
	Initialize(ctx context.Context) error

	LogAudit(ctx context.Context, entry *AuditEntry) error

	SaveSession(ctx context.Context, session *Session) error

	LoadSession(ctx context.Context, id string) (*Session, error)

	DeleteSession(ctx context.Context, id string) error

	ListSessions(ctx context.Context) ([]*Session, error)

	SaveScanCache(ctx context.Context, cache *ScanCache) error

	LoadScanCache(ctx context.Context, key string) (*ScanCache, error)

	Close() error
}

type AuditEntry struct {
	Timestamp time.Time `json:"timestamp"`

	SessionID string `json:"sessionID"`

	Plugin string `json:"plugin"`

	Action string `json:"action"`

	Target string `json:"target"`

	Result map[string]interface{} `json:"result"`

	Metadata map[string]interface{} `json:"metadata"`
}

type Session struct {
	ID string `json:"id"`

	Plugin string `json:"plugin"`

	Target string `json:"target"`

	Artifacts []Artifact `json:"artifacts"`

	CleanupActions []CleanupAction `json:"cleanupActions"`

	CreatedAt time.Time `json:"createdAt"`

	UpdatedAt time.Time `json:"updatedAt"`

	Status string `json:"status"`

	Metadata map[string]interface{} `json:"metadata"`
}

type Artifact struct {
	Type string `json:"type"`

	ID string `json:"id"`

	URL string `json:"url"`

	CreatedAt time.Time `json:"createdAt"`

	Metadata map[string]interface{} `json:"metadata"`
}

type CleanupAction struct {
	Type string `json:"type"`

	Params map[string]interface{} `json:"params"`
}

type ScanCache struct {
	Key string `json:"key"`

	URL string `json:"url"`

	Results interface{} `json:"results"`

	CachedAt time.Time `json:"cached_at"`

	// TTL is in seconds.
	TTL int64 `json:"ttl"`

	ExpiresAt time.Time `json:"expires_at"`
}
