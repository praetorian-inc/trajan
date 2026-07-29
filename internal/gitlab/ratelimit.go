package gitlab

import (
	"net/http"
	"strconv"
	"sync"
)

// RateLimiter tracks GitLab's RateLimit-* response headers (no X- prefix). The
// request loop reacts to 429 with Retry-After; this only keeps the latest
// limit/remaining snapshot for the whoami report.
type RateLimiter struct {
	mu        sync.Mutex
	limit     int
	remaining int
}

func NewRateLimiter() *RateLimiter { return &RateLimiter{limit: 2000, remaining: 2000} }

func (l *RateLimiter) Update(h http.Header) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if v := h.Get("RateLimit-Limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			l.limit = n
		}
	}
	if v := h.Get("RateLimit-Remaining"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			l.remaining = n
		}
	}
}

func (l *RateLimiter) Snapshot() (limit, remaining int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.limit, l.remaining
}
