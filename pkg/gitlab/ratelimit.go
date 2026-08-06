package gitlab

import (
	"time"

	"github.com/praetorian-inc/trajan/pkg/platforms/shared/ratelimit"
)

// GitLab allows ~300 req/min on the free tier and 2000 on Premium/Ultimate.
type RateLimiter struct {
	*ratelimit.Limiter
}

func NewRateLimiter() *RateLimiter {
	return &RateLimiter{
		Limiter: ratelimit.New(ratelimit.Config{
			HeaderPrefix:       "RateLimit-", // GitLab uses NO X- prefix
			DefaultLimit:       2000,
			DefaultRemaining:   2000,
			ThresholdPercent:   10,
			ResetDuration:      time.Minute,
			SupportsRetryAfter: false, // GitLab doesn't support secondary rate limits
		}),
	}
}
