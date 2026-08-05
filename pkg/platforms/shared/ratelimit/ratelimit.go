package ratelimit

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"
)

type Config struct {
	// Examples: "X-RateLimit-" (GitHub, Bitbucket), "RateLimit-" (GitLab)
	HeaderPrefix string

	// Examples: 5000 (GitHub), 2000 (GitLab), 1000 (Bitbucket)
	DefaultLimit int

	// Typically same as DefaultLimit
	DefaultRemaining int

	// Examples: 5 (GitHub), 10 (GitLab, Bitbucket)
	ThresholdPercent int

	// Examples: 1 hour (GitHub, Bitbucket), 1 minute (GitLab)
	ResetDuration time.Duration

	// true for GitHub (secondary rate limits), false for GitLab/Bitbucket
	SupportsRetryAfter bool
}

type Limiter struct {
	config     Config
	remaining  int
	limit      int
	reset      time.Time
	retryAfter time.Time // Secondary rate limit (optional, GitHub only)
	mu         sync.RWMutex
}

func New(config Config) *Limiter {
	return &Limiter{
		config:    config,
		remaining: config.DefaultRemaining,
		limit:     config.DefaultLimit,
		reset:     time.Now().Add(config.ResetDuration),
	}
}

func (l *Limiter) Update(header http.Header) {
	l.mu.Lock()
	defer l.mu.Unlock()

	remainingHeader := l.config.HeaderPrefix + "Remaining"
	limitHeader := l.config.HeaderPrefix + "Limit"
	resetHeader := l.config.HeaderPrefix + "Reset"

	if remaining := header.Get(remainingHeader); remaining != "" {
		l.remaining, _ = strconv.Atoi(remaining)
	}
	if limit := header.Get(limitHeader); limit != "" {
		l.limit, _ = strconv.Atoi(limit)
	}
	if reset := header.Get(resetHeader); reset != "" {
		unix, _ := strconv.ParseInt(reset, 10, 64)
		l.reset = time.Unix(unix, 0)
	}

	if l.config.SupportsRetryAfter {
		if retryAfter := header.Get("Retry-After"); retryAfter != "" {
			seconds, _ := strconv.Atoi(retryAfter)
			l.retryAfter = time.Now().Add(time.Duration(seconds) * time.Second)
		}
	}
}

func (l *Limiter) ShouldThrottle() bool {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if l.limit == 0 {
		return false
	}

	threshold := l.limit * l.config.ThresholdPercent / 100
	return l.remaining < threshold
}

// Retry-After wins over the primary-limit threshold, per GitHub's guidance;
// above the threshold it returns immediately.
func (l *Limiter) Wait(ctx context.Context) error {
	if l.config.SupportsRetryAfter {
		l.mu.RLock()
		retryAfter := l.retryAfter
		l.mu.RUnlock()

		if !retryAfter.IsZero() && time.Now().Before(retryAfter) {
			waitDuration := time.Until(retryAfter)

			select {
			case <-time.After(waitDuration):
				l.mu.Lock()
				l.retryAfter = time.Time{}
				l.mu.Unlock()
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}

	if !l.ShouldThrottle() {
		return nil
	}

	l.mu.RLock()
	remaining := l.remaining
	limit := l.limit
	waitDuration := time.Until(l.reset) + time.Second
	l.mu.RUnlock()

	if waitDuration <= 0 {
		return nil
	}

	// Unconditional: the user needs to know why the scan stalled.
	fmt.Fprintf(os.Stderr, "Rate limit approaching (%d/%d remaining), pausing for %v...\n", remaining, limit, waitDuration)

	select {
	case <-time.After(waitDuration):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (l *Limiter) Remaining() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.remaining
}

func (l *Limiter) Limit() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.limit
}

func (l *Limiter) ResetTime() time.Time {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.reset
}

// Zero time when unsupported or unset.
func (l *Limiter) RetryAfter() time.Time {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.retryAfter
}
