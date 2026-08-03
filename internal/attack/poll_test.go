package attack

import (
	"context"
	"errors"
	"testing"
	"time"
)

// A zero interval is a program bug, and time.After(0) turns it into a read loop
// bounded only by the transport. It must be refused before the first read, and
// it must not be reported as a timeout: the deadline has not passed.
func TestPollRefusesANonPositiveInterval(t *testing.T) {
	reads := 0
	_, err := poll(t.Context(), 0, 5*time.Minute, nil,
		func(context.Context) (int, bool, any, error) {
			reads++
			return 0, false, "cursor", nil
		})
	if err == nil {
		t.Fatal("a zero interval must be refused")
	}
	if errors.Is(err, errTimedOut) {
		t.Errorf("a zero interval is not an expired deadline: %v", err)
	}
	if reads != 0 {
		t.Errorf("nothing may be read before the interval is checked; %d read(s) issued", reads)
	}
}

// Expiry is decided on the time left, not on the wait that time was clamped to:
// an interval far longer than the timeout must still be cut short, and the poll
// must end on the deadline rather than sleeping the whole interval.
func TestPollExpiresOnRemainingTimeNotTheClampedWait(t *testing.T) {
	reads := 0
	start := time.Now()
	_, err := poll(t.Context(), time.Hour, 20*time.Millisecond, nil,
		func(context.Context) (int, bool, any, error) {
			reads++
			return 0, false, "cursor", nil
		})
	if !errors.Is(err, errTimedOut) {
		t.Fatalf("want a timeout, got %v", err)
	}
	if elapsed := time.Since(start); elapsed < 20*time.Millisecond {
		t.Errorf("the poll gave up after %s, before its %s deadline", elapsed, 20*time.Millisecond)
	}
	if reads < 2 {
		t.Errorf("the wait must be clamped to the time left and read again; %d read(s) issued", reads)
	}
}

// The cursor a read hands back beside an error is the latest state of the watch.
// Losing it makes the next resume correlate from scratch, so it is checkpointed
// before the error ends the poll.
func TestPollCheckpointsTheCursorOfAFailedRead(t *testing.T) {
	var seen []any
	readErr := errors.New("401 from the transport")
	_, err := poll(t.Context(), time.Millisecond, 0, func(c any) error { seen = append(seen, c); return nil },
		func(context.Context) (int, bool, any, error) {
			return 0, false, "run-42", readErr
		})
	if !errors.Is(err, readErr) {
		t.Fatalf("the read error must reach the caller, got %v", err)
	}
	if len(seen) != 1 || seen[0] != "run-42" {
		t.Fatalf("the failed read's cursor must be checkpointed, got %v", seen)
	}
}

// A read that reports no cursor must not overwrite the one already on disk.
func TestPollDoesNotCheckpointAnAbsentCursor(t *testing.T) {
	checkpoints := 0
	_, err := poll(t.Context(), time.Millisecond, 0, func(any) error { checkpoints++; return nil },
		func(context.Context) (int, bool, any, error) { return 7, true, nil, nil })
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	if checkpoints != 0 {
		t.Fatalf("a nil cursor must not be written back, got %d checkpoint(s)", checkpoints)
	}
}

func TestPollHonoursCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	_, err := poll(ctx, time.Hour, 0, nil,
		func(context.Context) (int, bool, any, error) {
			cancel()
			return 0, false, "cursor", nil
		})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
}
