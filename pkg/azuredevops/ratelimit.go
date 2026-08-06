package azuredevops

import (
	"context"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// TSTU (Time-Shared Throughput Unit): ADO allows 200 per 5-minute sliding window per user.
type RateLimiter struct {
	remaining int
	limit     int
	reset     time.Time
	mu        sync.RWMutex
}

func NewRateLimiter() *RateLimiter {
	return &RateLimiter{
		remaining: 200,
		limit:     200,
		reset:     time.Now().Add(5 * time.Minute),
	}
}

func (r *RateLimiter) Update(header http.Header) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if remaining := header.Get("X-RateLimit-Remaining"); remaining != "" {
		r.remaining, _ = strconv.Atoi(remaining)
	}
	if limit := header.Get("X-RateLimit-Limit"); limit != "" {
		r.limit, _ = strconv.Atoi(limit)
	}
	if reset := header.Get("X-RateLimit-Reset"); reset != "" {
		unix, _ := strconv.ParseInt(reset, 10, 64)
		r.reset = time.Unix(unix, 0)
	}
}

func (r *RateLimiter) ShouldThrottle() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if r.limit == 0 {
		return false // No rate limit information available
	}
	threshold := r.limit / 10
	return r.remaining < threshold
}

func (r *RateLimiter) Wait(ctx context.Context) error {
	if !r.ShouldThrottle() {
		return nil
	}

	r.mu.RLock()
	waitDuration := time.Until(r.reset) + time.Second
	r.mu.RUnlock()

	if waitDuration <= 0 {
		return nil
	}

	select {
	case <-time.After(waitDuration):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (r *RateLimiter) Remaining() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.remaining
}

func (r *RateLimiter) Limit() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.limit
}

func (r *RateLimiter) ResetTime() time.Time {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.reset
}
