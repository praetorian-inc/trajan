package gitlab

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRateLimiter_NewRateLimiter(t *testing.T) {
	rl := NewRateLimiter()

	// 2000 req/min is the premium-tier default.
	assert.Equal(t, 2000, rl.Limit())
	assert.Equal(t, 2000, rl.Remaining())
	assert.False(t, rl.ResetTime().IsZero())
}
