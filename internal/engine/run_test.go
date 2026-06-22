package engine

import (
	"context"
	"errors"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestRun_Concurrency(t *testing.T) {
	const limit = 3
	const n = 50

	var inFlight int32
	var maxInFlight int32

	items := make([]int, n)
	for i := range items {
		items[i] = i
	}

	out, err := Run(context.Background(), limit, items, func(_ context.Context, i int) (int, error) {
		cur := atomic.AddInt32(&inFlight, 1)
		for {
			m := atomic.LoadInt32(&maxInFlight)
			if cur <= m || atomic.CompareAndSwapInt32(&maxInFlight, m, cur) {
				break
			}
		}
		time.Sleep(time.Millisecond) // force contention so the limit is actually exercised
		atomic.AddInt32(&inFlight, -1)
		return i * 2, nil
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(out) != n {
		t.Fatalf("len(out) = %d, want %d", len(out), n)
	}
	if maxInFlight > limit {
		t.Fatalf("maxInFlight = %d, exceeds limit %d", maxInFlight, limit)
	}
	sort.Ints(out)
	for i := 0; i < n; i++ {
		if out[i] != i*2 {
			t.Fatalf("out[%d] = %d, want %d", i, out[i], i*2)
		}
	}
}

func TestRun_FirstErrorCancels(t *testing.T) {
	wantErr := errors.New("item 7 failed")
	items := make([]int, 100)
	for i := range items {
		items[i] = i
	}

	out, err := Run(context.Background(), 4, items, func(ctx context.Context, i int) (int, error) {
		if i == 7 {
			return 0, wantErr
		}
		// Block on ctx so non-failing goroutines unwind on cancel rather than racing
		// to completion, which would make the out!=nil assertion flaky.
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-time.After(50 * time.Millisecond):
			return i, nil
		}
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("err = %v, want %v", err, wantErr)
	}
	if out != nil {
		t.Fatalf("out = %v, want nil on error", out)
	}
}

func TestRunPartial_DropsBadItem(t *testing.T) {
	items := []int{1, 2, 3, 4, 5}
	badItem := 3

	var mu sync.Mutex
	var onErrItems []int
	var onErrCalls int

	out := RunPartial(context.Background(), 2, items,
		func(_ context.Context, i int) (int, error) {
			if i == badItem {
				return 0, errors.New("bad")
			}
			return i * 10, nil
		},
		func(i int, err error) {
			mu.Lock()
			onErrCalls++
			onErrItems = append(onErrItems, i)
			mu.Unlock()
		},
	)

	if onErrCalls != 1 {
		t.Fatalf("onError calls = %d, want 1", onErrCalls)
	}
	if len(onErrItems) != 1 || onErrItems[0] != badItem {
		t.Fatalf("onError items = %v, want [%d]", onErrItems, badItem)
	}
	if len(out) != len(items)-1 {
		t.Fatalf("len(out) = %d, want %d", len(out), len(items)-1)
	}
	sort.Ints(out)
	want := []int{10, 20, 40, 50}
	for i := range want {
		if out[i] != want[i] {
			t.Fatalf("out = %v, want %v", out, want)
		}
	}
}

func TestRunPartial_NilOnError(t *testing.T) {
	items := []int{1, 2, 3}
	out := RunPartial(context.Background(), 2, items,
		func(_ context.Context, i int) (int, error) {
			if i == 2 {
				return 0, errors.New("bad")
			}
			return i, nil
		}, nil)
	if len(out) != 2 {
		t.Fatalf("len(out) = %d, want 2", len(out))
	}
}
