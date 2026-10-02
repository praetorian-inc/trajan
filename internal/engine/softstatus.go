package engine

import (
	"context"
	"strconv"
	"sync"
)

type softTallyKey struct{}

// Soft-fail helpers return nil after marking, so without this a forbidden surface reads as collected.
type SoftTally struct {
	mu     sync.Mutex
	status int
}

func WithSoftTally(ctx context.Context) (context.Context, *SoftTally) {
	t := &SoftTally{}
	return context.WithValue(ctx, softTallyKey{}, t), t
}

func RecordSoft(ctx context.Context, status int) {
	if status == 0 {
		return
	}
	t, _ := ctx.Value(softTallyKey{}).(*SoftTally)
	if t == nil {
		return
	}
	t.mu.Lock()
	if softRank(status) > softRank(t.status) {
		t.status = status
	}
	t.mu.Unlock()
}

// A denial outranks an absence, and anything else outranks both.
func softRank(status int) int {
	switch status {
	case 0:
		return 0
	case 404:
		return 1
	case 403:
		return 2
	}
	return 3
}

func (t *SoftTally) Surface() (status, reason string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	switch t.status {
	case 0:
		return "ok", ""
	case 404:
		return "skipped", "HTTP 404"
	}
	return "degraded", "HTTP " + strconv.Itoa(t.status)
}
