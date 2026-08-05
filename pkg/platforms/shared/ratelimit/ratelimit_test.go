package ratelimit

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLimiter_Update_WithXPrefix(t *testing.T) {
	config := Config{
		HeaderPrefix:     "X-RateLimit-",
		DefaultLimit:     5000,
		DefaultRemaining: 5000,
		ThresholdPercent: 5,
		ResetDuration:    time.Hour,
	}
	limiter := New(config)

	header := http.Header{}
	header.Set("X-RateLimit-Remaining", "100")
	header.Set("X-RateLimit-Limit", "5000")
	header.Set("X-RateLimit-Reset", "1700000000")

	limiter.Update(header)

	assert.Equal(t, 100, limiter.Remaining())
	assert.Equal(t, 5000, limiter.Limit())
	assert.Equal(t, time.Unix(1700000000, 0), limiter.ResetTime())
}

func TestLimiter_Update_WithoutXPrefix(t *testing.T) {
	config := Config{
		HeaderPrefix:     "RateLimit-",
		DefaultLimit:     2000,
		DefaultRemaining: 2000,
		ThresholdPercent: 10,
		ResetDuration:    time.Minute,
	}
	limiter := New(config)

	header := http.Header{}
	header.Set("RateLimit-Remaining", "1000")
	header.Set("RateLimit-Limit", "2000")
	header.Set("RateLimit-Reset", "1735776000")

	limiter.Update(header)

	assert.Equal(t, 1000, limiter.Remaining())
	assert.Equal(t, 2000, limiter.Limit())
	assert.Equal(t, time.Unix(1735776000, 0), limiter.ResetTime())
}

func TestLimiter_ShouldThrottle_GitHub(t *testing.T) {
	config := Config{
		HeaderPrefix:     "X-RateLimit-",
		DefaultLimit:     5000,
		DefaultRemaining: 5000,
		ThresholdPercent: 5,
	}
	limiter := New(config)

	tests := []struct {
		name      string
		remaining int
		limit     int
		want      bool
	}{
		{
			name:      "10% remaining - should not throttle",
			remaining: 500,
			limit:     5000,
			want:      false,
		},
		{
			name:      "4% remaining - should throttle",
			remaining: 200,
			limit:     5000,
			want:      true,
		},
		{
			name:      "Exactly at 5% - should not throttle",
			remaining: 250,
			limit:     5000,
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			limiter.mu.Lock()
			limiter.remaining = tt.remaining
			limiter.limit = tt.limit
			limiter.mu.Unlock()

			assert.Equal(t, tt.want, limiter.ShouldThrottle())
		})
	}
}

func TestLimiter_ShouldThrottle_GitLab(t *testing.T) {
	config := Config{
		HeaderPrefix:     "RateLimit-",
		DefaultLimit:     2000,
		DefaultRemaining: 2000,
		ThresholdPercent: 10,
	}
	limiter := New(config)

	tests := []struct {
		name      string
		remaining int
		limit     int
		want      bool
	}{
		{
			name:      "50% remaining - should not throttle",
			remaining: 1000,
			limit:     2000,
			want:      false,
		},
		{
			name:      "At threshold (10%) - should not throttle",
			remaining: 200,
			limit:     2000,
			want:      false,
		},
		{
			name:      "Below threshold (5%) - should throttle",
			remaining: 100,
			limit:     2000,
			want:      true,
		},
		{
			name:      "Zero remaining - should throttle",
			remaining: 0,
			limit:     2000,
			want:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			limiter.mu.Lock()
			limiter.remaining = tt.remaining
			limiter.limit = tt.limit
			limiter.mu.Unlock()

			assert.Equal(t, tt.want, limiter.ShouldThrottle())
		})
	}
}

func TestLimiter_Wait_ContextCanceled(t *testing.T) {
	config := Config{
		DefaultLimit:     5000,
		DefaultRemaining: 100, // 2% - below 5% threshold
		ThresholdPercent: 5,
	}
	limiter := New(config)

	limiter.mu.Lock()
	limiter.remaining = 100
	limiter.limit = 5000
	limiter.reset = time.Now().Add(10 * time.Second)
	limiter.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	err := limiter.Wait(ctx)
	require.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestLimiter_Concurrent(t *testing.T) {
	config := Config{
		HeaderPrefix:     "RateLimit-",
		DefaultLimit:     2000,
		DefaultRemaining: 2000,
		ThresholdPercent: 10,
	}
	limiter := New(config)

	header := http.Header{}
	header.Set("RateLimit-Limit", "2000")
	header.Set("RateLimit-Remaining", "1000")

	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			limiter.Update(header)
			_ = limiter.Remaining()
			_ = limiter.Limit()
			_ = limiter.ShouldThrottle()
			done <- true
		}()
	}

	for i := 0; i < 10; i++ {
		<-done
	}

	assert.Equal(t, 2000, limiter.Limit())
	assert.Equal(t, 1000, limiter.Remaining())
}

func TestLimiter_WithoutRetryAfter(t *testing.T) {
	config := Config{
		HeaderPrefix:       "RateLimit-",
		DefaultLimit:       2000,
		DefaultRemaining:   2000,
		ThresholdPercent:   10,
		SupportsRetryAfter: false,
	}
	limiter := New(config)

	header := http.Header{}
	header.Set("Retry-After", "30")

	limiter.Update(header)

	retryAfter := limiter.RetryAfter()
	assert.True(t, retryAfter.IsZero(), "RetryAfter should be zero when not supported")
}
