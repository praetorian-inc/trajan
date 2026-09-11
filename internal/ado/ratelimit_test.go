package ado

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRateLimiterNextDecides(t *testing.T) {
	reset := time.Now().Add(90 * time.Second)
	cases := []struct {
		name string
		r    *rateLimiter
		want bool
	}{
		{"no headers seen yet", &rateLimiter{}, false},
		{"plenty remaining", &rateLimiter{remaining: 200, limit: 200, reset: reset}, false},
		{"exactly at the threshold", &rateLimiter{remaining: 20, limit: 200, reset: reset}, false},
		{"below the threshold", &rateLimiter{remaining: 19, limit: 200, reset: reset}, true},
		{"window already reset", &rateLimiter{remaining: 0, limit: 200, reset: time.Now().Add(-time.Minute)}, false},
		{"delay outranks a healthy budget", &rateLimiter{remaining: 200, limit: 200, delay: 4}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.r.next() > 0; got != tc.want {
				t.Fatalf("next() > 0 = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestRateLimiterDelayIsConsumedOnce(t *testing.T) {
	r := &rateLimiter{delay: 5}
	if d := r.next(); d != 5*time.Second {
		t.Fatalf("first next() = %v, want 5s", d)
	}
	if d := r.next(); d != 0 {
		t.Fatalf("second next() = %v, want 0", d)
	}
}

func TestRateLimiterKeepsTheLongestDelay(t *testing.T) {
	var r rateLimiter
	r.update(http.Header{"X-Ratelimit-Delay": []string{"3"}})
	r.update(http.Header{"X-Ratelimit-Delay": []string{"7"}})
	r.update(http.Header{"X-Ratelimit-Delay": []string{"1"}})
	if d := r.next(); d != 7*time.Second {
		t.Fatalf("next() = %v, want 7s", d)
	}
}

func TestDelayHeaderPacesTheNextRequest(t *testing.T) {
	var slept []float64
	prev := sleepFn
	sleepFn = func(_ context.Context, sec float64) { slept = append(slept, sec) }
	t.Cleanup(func() { sleepFn = prev })

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-RateLimit-Delay", "6")
		w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(srv.Close)
	prevBase := hostBase["core"]
	hostBase["core"] = srv.URL
	t.Cleanup(func() { hostBase["core"] = prevBase })

	c := NewClient("org", "pat")
	for range 3 {
		if _, _, err := c.Get(context.Background(), "core", APIVersion, "/x", nil, false); err != nil {
			t.Fatalf("Get: %v", err)
		}
	}
	if len(slept) != 2 || slept[0] != 6 || slept[1] != 6 {
		t.Fatalf("slept = %v, want two 6s waits", slept)
	}
}
