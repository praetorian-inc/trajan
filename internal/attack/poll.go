package attack

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// errTimedOut ends a bounded poll. It is not by itself a step failure: poll
// returns no value with it, and every caller catches it and reports what its own
// cursor last saw, because an absent run is inconclusive rather than proof that
// nothing ran.
var errTimedOut = errors.New("timed out")

// poll drives every wait in the subsystem. fn performs one read and reports
// (value, done, nextCursor, err); the cursor is checkpointed after every read,
// which is what lets a watch killed on day two resume as a watch instead of
// re-running the step that caused it. A zero timeout waits indefinitely —
// kill-bounded only, still checkpointing.
func poll[T any](
	ctx context.Context,
	interval, timeout time.Duration,
	checkpoint func(cursor any) error,
	fn func(context.Context) (T, bool, any, error),
) (T, error) {
	var zero T
	// A non-positive interval is a program bug, and it is refused before the first
	// read rather than after it: time.After(0) fires immediately, so the loop would
	// read the customer's API as fast as the transport allows.
	if interval <= 0 {
		return zero, fmt.Errorf("poll interval must be positive, got %s", interval)
	}
	var deadline time.Time
	if timeout > 0 {
		deadline = time.Now().Add(timeout)
	}
	for {
		v, done, cursor, err := fn(ctx)
		// The cursor a read hands back beside an error is still the latest state of
		// the watch, so it is checkpointed before the error decides the outcome:
		// otherwise a failed read discards the correlation a resume would pick up.
		if checkpoint != nil && cursor != nil {
			if cerr := checkpoint(cursor); cerr != nil {
				return zero, errors.Join(err, cerr)
			}
		}
		if err != nil {
			return zero, err
		}
		if done {
			return v, nil
		}
		wait := interval
		if !deadline.IsZero() {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				return zero, fmt.Errorf("%w after %s", errTimedOut, timeout)
			}
			wait = min(wait, remaining)
		}
		select {
		case <-ctx.Done():
			return zero, ctx.Err()
		case <-time.After(wait):
		}
	}
}

// parseTimeout reads a waiting primitive's timeout: field. Omitting it is the
// spelling of an unbounded human wait, so an empty value is zero rather than an
// error.
func parseTimeout(raw string) (time.Duration, error) {
	if strings.TrimSpace(raw) == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("timeout %q: %w", raw, err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("timeout %q must be positive; omit timeout: to wait indefinitely", raw)
	}
	return d, nil
}

func boundText(timeout time.Duration) string {
	if timeout == 0 {
		return "indefinitely (kill-bounded, checkpointing every poll)"
	}
	return "for up to " + timeout.String()
}
