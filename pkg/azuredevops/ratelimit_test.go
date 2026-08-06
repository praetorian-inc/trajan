package azuredevops

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRateLimiter_NewRateLimiter(t *testing.T) {
	rl := NewRateLimiter()

	// ADO default: 200 TSTUs per 5-minute window.
	assert.Equal(t, 200, rl.Limit())
	assert.Equal(t, 200, rl.Remaining())
	assert.False(t, rl.ResetTime().IsZero())
}

func TestRateLimiter_Update(t *testing.T) {
	rl := NewRateLimiter()

	header := http.Header{}
	header.Set("X-RateLimit-Limit", "200")
	header.Set("X-RateLimit-Remaining", "150")
	header.Set("X-RateLimit-Reset", "1735776000") // 2025-01-02 00:00:00 UTC

	rl.Update(header)

	assert.Equal(t, 200, rl.Limit())
	assert.Equal(t, 150, rl.Remaining())
	assert.Equal(t, time.Unix(1735776000, 0), rl.ResetTime())
}

func TestRateLimiter_UpdateWithMissingHeaders(t *testing.T) {
	rl := NewRateLimiter()

	rl.mu.Lock()
	rl.limit = 200
	rl.remaining = 150
	rl.reset = time.Unix(1735776000, 0)
	rl.mu.Unlock()

	emptyHeader := http.Header{}
	rl.Update(emptyHeader)

	assert.Equal(t, 200, rl.Limit())
	assert.Equal(t, 150, rl.Remaining())
	assert.Equal(t, time.Unix(1735776000, 0), rl.ResetTime())
}

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

			rl.mu.Lock()
			rl.limit = tt.limit
			rl.remaining = tt.remaining
			rl.mu.Unlock()

			assert.Equal(t, tt.want, rl.ShouldThrottle())
		})
	}
}

func TestRateLimiter_Wait(t *testing.T) {
	t.Run("No throttle needed", func(t *testing.T) {
		rl := NewRateLimiter()
		ctx := context.Background()

		// Above the 10% threshold.
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

		// Below the 10% threshold.
		rl.mu.Lock()
		rl.limit = 200
		rl.remaining = 5
		rl.reset = time.Now().Add(10 * time.Second)
		rl.mu.Unlock()

		cancel()

		err := rl.Wait(ctx)
		require.Error(t, err)
		assert.Equal(t, context.Canceled, err)
	})

	t.Run("Reset time in past should not wait", func(t *testing.T) {
		rl := NewRateLimiter()
		ctx := context.Background()

		rl.mu.Lock()
		rl.limit = 200
		rl.remaining = 5
		rl.reset = time.Now().Add(-1 * time.Second)
		rl.mu.Unlock()

		start := time.Now()
		err := rl.Wait(ctx)
		elapsed := time.Since(start)

		require.NoError(t, err)
		assert.Less(t, elapsed, 10*time.Millisecond, "Should not wait when reset is in past")
	})
}

func TestRateLimiter_Concurrent(t *testing.T) {
	rl := NewRateLimiter()

	header := http.Header{}
	header.Set("X-RateLimit-Limit", "200")
	header.Set("X-RateLimit-Remaining", "100")
	header.Set("X-RateLimit-Reset", "1735776000")

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

	for i := 0; i < 10; i++ {
		<-done
	}

	assert.Equal(t, 200, rl.Limit())
	assert.Equal(t, 100, rl.Remaining())
	assert.Equal(t, time.Unix(1735776000, 0), rl.ResetTime())
}
