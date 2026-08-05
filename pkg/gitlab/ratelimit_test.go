package gitlab

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestRateLimiter_NewRateLimiter tests default initialization
func TestRateLimiter_NewRateLimiter(t *testing.T) {
	rl := NewRateLimiter()

	// GitLab default rate limit is 2000 req/min (premium tier)
	assert.Equal(t, 2000, rl.Limit())
	assert.Equal(t, 2000, rl.Remaining())
	assert.False(t, rl.ResetTime().IsZero())
}
