package scanner

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"sync/atomic"
	"time"

	"github.com/praetorian-inc/trajan/pkg/detections"
)

type ScanResultCache struct {
	entries map[string]*ScanCacheEntry
	mu      sync.RWMutex
	ttl     time.Duration
	hits    int64
	misses  int64
}

type ScanCacheEntry struct {
	Findings    []detections.Finding
	CachedAt    time.Time
	ExpiresAt   time.Time
	ContentHash string
}

func (c *ScanResultCache) Get(repoSlug, workflowPath, content string) ([]detections.Finding, bool) {
	key := contentHash(repoSlug, workflowPath, content)

	c.mu.RLock()
	entry, ok := c.entries[key]
	c.mu.RUnlock()

	if !ok {
		atomic.AddInt64(&c.misses, 1)
		return nil, false
	}

	if time.Now().After(entry.ExpiresAt) {
		atomic.AddInt64(&c.misses, 1)
		return nil, false
	}

	atomic.AddInt64(&c.hits, 1)
	return entry.Findings, true
}

func (c *ScanResultCache) Set(repoSlug, workflowPath, content string, findings []detections.Finding) {
	key := contentHash(repoSlug, workflowPath, content)

	c.mu.Lock()
	defer c.mu.Unlock()

	entry := &ScanCacheEntry{
		Findings:    findings,
		CachedAt:    time.Now(),
		ExpiresAt:   time.Now().Add(c.ttl),
		ContentHash: key,
	}

	c.entries[key] = entry
}

func contentHash(repoSlug, workflowPath, content string) string {
	h := sha256.New()
	h.Write([]byte(repoSlug + ":" + workflowPath + ":" + content))
	return hex.EncodeToString(h.Sum(nil))
}
