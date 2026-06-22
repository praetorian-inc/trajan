package engine

import (
	"context"
	"sync"

	"golang.org/x/sync/errgroup"
)

// Run fans fn over items with at most limit concurrent calls; the first error
// cancels the group. Results are in completion order, not input order — embed the
// key in the result if pairing is needed.
func Run[I, O any](ctx context.Context, limit int, items []I, fn func(context.Context, I) (O, error)) ([]O, error) {
	if limit < 1 {
		limit = 1
	}
	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(limit)
	var mu sync.Mutex
	out := make([]O, 0, len(items))
	for _, it := range items {
		g.Go(func() error {
			o, err := fn(ctx, it)
			if err != nil {
				return err
			}
			mu.Lock()
			out = append(out, o)
			mu.Unlock()
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}
	return out, nil
}

// RunPartial is like Run but routes a per-item failure to onError and drops the
// item instead of aborting the batch. Results are in completion order.
func RunPartial[I, O any](ctx context.Context, limit int, items []I,
	fn func(context.Context, I) (O, error), onError func(I, error)) []O {
	if limit < 1 {
		limit = 1
	}
	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(limit)
	var mu sync.Mutex
	out := make([]O, 0, len(items))
	for _, it := range items {
		g.Go(func() error {
			o, err := fn(ctx, it)
			if err != nil {
				if onError != nil {
					onError(it, err)
				}
				return nil
			}
			mu.Lock()
			out = append(out, o)
			mu.Unlock()
			return nil
		})
	}
	_ = g.Wait()
	return out
}
