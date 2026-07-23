package ado

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/praetorian-inc/trajan/internal/engine"
)

func engineCP(dir string) engine.CurrentPhase { return engine.CurrentPhase{RunDir: dir} }

func readData(t *testing.T, dir, rel string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, rel))
	if err != nil {
		t.Fatal(err)
	}
	var env struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(b, &env); err != nil {
		t.Fatal(err)
	}
	return env.Data
}

func withServer(t *testing.T, h http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	prev := hostBase["core"]
	hostBase["core"] = srv.URL
	t.Cleanup(func() { hostBase["core"] = prev })
	return NewClient("org", "pat")
}

// Paginate must follow the x-ms-continuationtoken header and accumulate value[].
func TestPaginate_Continuation(t *testing.T) {
	c := withServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("continuationToken") == "" {
			w.Header().Set("x-ms-continuationtoken", "TOK")
			w.Write([]byte(`{"count":2,"value":[{"id":1},{"id":2}]}`))
			return
		}
		w.Write([]byte(`{"count":1,"value":[{"id":3}]}`))
	})
	items, err := c.Paginate(context.Background(), "core", APIVersion, "/list", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 3 {
		t.Fatalf("want 3 items across 2 pages, got %d", len(items))
	}
}

// A non-envelope (single object) body is returned as one item, not treated as a list.
func TestPaginate_SingleObject(t *testing.T) {
	c := withServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"enforceJobAuthScope":true}`))
	})
	items, err := c.Paginate(context.Background(), "core", APIVersion, "/generalsettings", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || !boolField(items[0], "enforceJobAuthScope") {
		t.Fatalf("single object not passed through: %v", items)
	}
}

func TestGet_Allow404(t *testing.T) {
	c := withServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusNotFound)
	})
	raw, _, err := c.Get(context.Background(), "core", APIVersion, "/missing", nil, true)
	if err != nil {
		t.Fatalf("allow404 should swallow 404: %v", err)
	}
	if raw != nil {
		t.Fatalf("want nil body on 404, got %s", raw)
	}
}

func TestSoftClassification(t *testing.T) {
	c := withServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	})
	_, _, err := c.Get(context.Background(), "core", APIVersion, "/x", nil, false)
	if err == nil || !isSoft(err) {
		t.Fatalf("403 should be soft, got %v", err)
	}
	if softStatus(err) != http.StatusForbidden {
		t.Fatalf("softStatus = %d", softStatus(err))
	}
	// a 500 is not soft
	if isSoft(&AdoError{Status: 500}) {
		t.Fatal("500 must not be soft")
	}
}

// A 429 with Retry-After must retry (not abort) and then succeed.
func TestRetryOn429(t *testing.T) {
	prev := sleepFn
	sleepFn = func(context.Context, float64) {}
	t.Cleanup(func() { sleepFn = prev })

	var calls atomic.Int32
	c := withServer(t, func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.Header().Set("Retry-After", "0")
			http.Error(w, "slow down", http.StatusTooManyRequests)
			return
		}
		w.Write([]byte(`{"ok":true}`))
	})
	raw, _, err := c.Get(context.Background(), "core", APIVersion, "/x", nil, false)
	if err != nil {
		t.Fatalf("expected success after retry, got %v", err)
	}
	var m map[string]any
	if json.Unmarshal(raw, &m); m["ok"] != true {
		t.Fatalf("unexpected body: %s", raw)
	}
	if calls.Load() != 2 {
		t.Fatalf("want 2 calls (429 then 200), got %d", calls.Load())
	}
}

// A retried POST (after 429) must re-send the body — an io.Reader would be at EOF.
func TestPostRetryResendsBody(t *testing.T) {
	prev := sleepFn
	sleepFn = func(context.Context, float64) {}
	t.Cleanup(func() { sleepFn = prev })

	var calls atomic.Int32
	var lastBody atomic.Value
	c := withServer(t, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		lastBody.Store(string(b))
		if calls.Add(1) == 1 {
			w.Header().Set("Retry-After", "0")
			http.Error(w, "slow down", http.StatusTooManyRequests)
			return
		}
		w.Write([]byte(`{"finalYaml":"ok"}`))
	})
	_, err := c.Post(context.Background(), "core", APIVersionPreview, "/preview", nil, map[string]any{"previewRun": true})
	if err != nil {
		t.Fatalf("post after retry failed: %v", err)
	}
	if got := lastBody.Load().(string); got != `{"previewRun":true}` {
		t.Fatalf("retried POST sent %q, want the original body", got)
	}
}

// A server that returns the SAME continuation token every page must not loop forever.
func TestPaginate_NonAdvancingTokenTerminates(t *testing.T) {
	var calls atomic.Int32
	c := withServer(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("x-ms-continuationtoken", "STUCK")
		w.Write([]byte(`{"count":1,"value":[{"id":1}]}`))
	})
	done := make(chan struct{})
	go func() {
		c.Paginate(context.Background(), "core", APIVersion, "/list", nil)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Paginate did not terminate on a non-advancing continuation token")
	}
	if calls.Load() != 2 {
		t.Fatalf("want 2 calls (page + one repeat then stop), got %d", calls.Load())
	}
}

func TestWriteOrMark(t *testing.T) {
	dir := t.TempDir()
	cp := engineCP(dir)
	// soft-failed surface -> marker
	if err := writeOrMark(cp, "x/marked.json", "t", "/p", nil, 403); err != nil {
		t.Fatal(err)
	}
	got := readData(t, dir, "x/marked.json")
	if got["_unobserved"] != float64(403) {
		t.Fatalf("want _unobserved:403 marker, got %v", got)
	}
	// success -> data
	if err := writeOrMark(cp, "x/ok.json", "t", "/p", []byte(`{"a":1}`), 0); err != nil {
		t.Fatal(err)
	}
	if readData(t, dir, "x/ok.json")["a"] != float64(1) {
		t.Fatal("data surface not written through")
	}
}

// HTML body (invalid PAT) is surfaced as an error, never stored as JSON.
func TestHTMLBodyIsError(t *testing.T) {
	c := withServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<!DOCTYPE html><html>sign in</html>"))
	})
	_, _, err := c.Get(context.Background(), "core", APIVersion, "/x", nil, false)
	if err == nil {
		t.Fatal("HTML response must be an error")
	}
}
