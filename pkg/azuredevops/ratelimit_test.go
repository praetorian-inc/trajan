package azuredevops

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRateLimiter_NewRateLimiter tests default initialization with TSTU values
func TestRateLimiter_NewRateLimiter(t *testing.T) {
	rl := NewRateLimiter()

	// Azure DevOps default: 200 TSTUs per 5-minute window
	assert.Equal(t, 200, rl.Limit())
	assert.Equal(t, 200, rl.Remaining())
	assert.False(t, rl.ResetTime().IsZero())
}

// TestRateLimiter_Update tests updating from Azure DevOps HTTP headers
func TestRateLimiter_Update(t *testing.T) {
	rl := NewRateLimiter()

	header := http.Header{}
	// Azure DevOps uses X-RateLimit-* headers (similar to BitBucket, not GitLab)
	header.Set("X-RateLimit-Limit", "200")
	header.Set("X-RateLimit-Remaining", "150")
	header.Set("X-RateLimit-Reset", "1735776000") // 2025-01-02 00:00:00 UTC

	rl.Update(header)

	assert.Equal(t, 200, rl.Limit())
	assert.Equal(t, 150, rl.Remaining())
	assert.Equal(t, time.Unix(1735776000, 0), rl.ResetTime())
}

// TestRateLimiter_UpdateWithMissingHeaders tests graceful handling of missing headers
func TestRateLimiter_UpdateWithMissingHeaders(t *testing.T) {
	rl := NewRateLimiter()

	// Set initial values
	rl.mu.Lock()
	rl.limit = 200
	rl.remaining = 150
	rl.reset = time.Unix(1735776000, 0)
	rl.mu.Unlock()

	// Update with empty headers - should not panic or change values
	emptyHeader := http.Header{}
	rl.Update(emptyHeader)

	// Values should remain unchanged
	assert.Equal(t, 200, rl.Limit())
	assert.Equal(t, 150, rl.Remaining())
	assert.Equal(t, time.Unix(1735776000, 0), rl.ResetTime())
}

// TestRateLimiter_ShouldThrottle tests TSTU-based throttling threshold
func TestRateLimiter_ShouldThrottle(t *testing.T) {
	tests := []struct {
		name      string
		limit     int
		remaining int
		want      bool
	}{
		{
			name:      "Above threshold (75% - 150 TSTUs)",
			limit:     200,
			remaining: 150,
			want:      false,
		},
		{
			name:      "At threshold (10% - 20 TSTUs)",
			limit:     200,
			remaining: 20,
			want:      false,
		},
		{
			name:      "Below threshold (5% - 10 TSTUs)",
			limit:     200,
			remaining: 10,
			want:      true,
		},
		{
			name:      "Very low (1% - 2 TSTUs)",
			limit:     200,
			remaining: 2,
			want:      true,
		},
		{
			name:      "Zero remaining TSTUs",
			limit:     200,
			remaining: 0,
			want:      true,
		},
		{
			name:      "Zero limit (no rate limit info)",
			limit:     0,
			remaining: 0,
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rl := NewRateLimiter()

			// Manually set values for test
			rl.mu.Lock()
			rl.limit = tt.limit
			rl.remaining = tt.remaining
			rl.mu.Unlock()

			assert.Equal(t, tt.want, rl.ShouldThrottle())
		})
	}
}

// TestRateLimiter_Wait tests wait behavior with TSTU threshold
func TestRateLimiter_Wait(t *testing.T) {
	t.Run("No throttle needed", func(t *testing.T) {
		rl := NewRateLimiter()
		ctx := context.Background()

		// Set remaining above threshold (>10% of 200 TSTUs)
		rl.mu.Lock()
		rl.limit = 200
		rl.remaining = 100
		rl.mu.Unlock()

		start := time.Now()
		err := rl.Wait(ctx)
		elapsed := time.Since(start)

		require.NoError(t, err)
		assert.Less(t, elapsed, 10*time.Millisecond, "Should not wait when above threshold")
	})

	t.Run("Context cancellation", func(t *testing.T) {
		rl := NewRateLimiter()
		ctx, cancel := context.WithCancel(context.Background())

		// Set to throttle (below 10% of 200 TSTUs)
		rl.mu.Lock()
		rl.limit = 200
		rl.remaining = 5
		rl.reset = time.Now().Add(10 * time.Second)
		rl.mu.Unlock()

		// Cancel immediately
		cancel()

		err := rl.Wait(ctx)
		require.Error(t, err)
		assert.Equal(t, context.Canceled, err)
	})

	t.Run("Reset time in past should not wait", func(t *testing.T) {
		rl := NewRateLimiter()
		ctx := context.Background()

		// Set to throttle but with reset time in past
		rl.mu.Lock()
		rl.limit = 200
		rl.remaining = 5
		rl.reset = time.Now().Add(-1 * time.Second) // Past
		rl.mu.Unlock()

		start := time.Now()
		err := rl.Wait(ctx)
		elapsed := time.Since(start)

		require.NoError(t, err)
		assert.Less(t, elapsed, 10*time.Millisecond, "Should not wait when reset is in past")
	})
}

// TestRateLimiter_Concurrent tests thread safety under concurrent access
func TestRateLimiter_Concurrent(t *testing.T) {
	rl := NewRateLimiter()

	header := http.Header{}
	// Azure DevOps headers (X- prefix, not RateLimit- prefix)
	header.Set("X-RateLimit-Limit", "200")
	header.Set("X-RateLimit-Remaining", "100")
	header.Set("X-RateLimit-Reset", "1735776000")

	// Run concurrent updates and reads
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			rl.Update(header)
			_ = rl.Remaining()
			_ = rl.Limit()
			_ = rl.ShouldThrottle()
			_ = rl.ResetTime()
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	// Verify state is consistent
	assert.Equal(t, 200, rl.Limit())
	assert.Equal(t, 100, rl.Remaining())
	assert.Equal(t, time.Unix(1735776000, 0), rl.ResetTime())
}
