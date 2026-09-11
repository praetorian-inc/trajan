package ado

import (
	"context"
	"net/http"
	"strconv"
	"sync"
	"time"
)

type rateLimiter struct {
	mu        sync.Mutex
	remaining int
	limit     int
	reset     time.Time
	delay     float64
}

func (r *rateLimiter) update(h http.Header) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if v := h.Get("X-RateLimit-Remaining"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			r.remaining = n
		}
	}
	if v := h.Get("X-RateLimit-Limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			r.limit = n
		}
	}
	if v := h.Get("X-RateLimit-Reset"); v != "" {
		if unix, err := strconv.ParseInt(v, 10, 64); err == nil {
			r.reset = time.Unix(unix, 0)
		}
	}
	if v := h.Get("X-RateLimit-Delay"); v != "" {
		if d, err := strconv.ParseFloat(v, 64); err == nil {
			r.delay = max(r.delay, d)
		}
	}
}

func (r *rateLimiter) next() time.Duration {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.delay > 0 {
		d := r.delay
		r.delay = 0
		return time.Duration(d * float64(time.Second))
	}
	if r.limit == 0 || r.remaining >= r.limit/10 {
		return 0
	}
	return time.Until(r.reset) + time.Second
}

func (r *rateLimiter) wait(ctx context.Context) {
	if d := r.next(); d > 0 {
		sleepFn(ctx, min(d.Seconds(), maxRateLimitSleep))
	}
}
