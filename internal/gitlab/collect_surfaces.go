package gitlab

import (
	"context"
	"encoding/json"
	"net/url"
	"time"

	"github.com/praetorian-inc/trajan/internal/engine"
)

const (
	collectorVer = "@0.1"
	sourceAPI    = "gitlab_rest"
	sourceGQL    = "gitlab_graphql"
)

var timeNow = time.Now

func nowISO() string { return engine.IsoformatUTC(timeNow()) }

type collectMeta struct {
	CollectedAt string         `json:"collected_at"`
	Collector   string         `json:"collector"`
	Source      collectMetaSrc `json:"source"`
}

type collectMetaSrc struct {
	API  string `json:"api"`
	Path string `json:"path"`
}

func envelope(cp engine.CurrentPhase, rel, collector, sourcePath string, data any) error {
	return envelopeSrc(cp, rel, collector, sourceAPI, sourcePath, data)
}

func envelopeSrc(cp engine.CurrentPhase, rel, collector, api, sourcePath string, data any) error {
	return cp.Write(rel, map[string]any{
		"_meta": collectMeta{
			CollectedAt: nowISO(),
			Collector:   collector + collectorVer,
			Source:      collectMetaSrc{API: api, Path: sourcePath},
		},
		"data": data,
	})
}

// writeOrMark writes the collected data, or a {"_unobserved":<status>} marker when
// the surface soft-failed (401/403/404) — so downstream can tell "no access" from
// "never collected".
func writeOrMark(cp engine.CurrentPhase, rel, collector, sourcePath string, raw json.RawMessage, status int) error {
	if status != 0 {
		return envelope(cp, rel, collector, sourcePath, map[string]any{"_unobserved": status})
	}
	return envelope(cp, rel, collector, sourcePath, raw)
}

// listOrMark returns the list (never nil) on success, or a {"_unobserved":<status>}
// marker on soft-fail — so a forbidden list never reads as "none exist".
func listOrMark(items []json.RawMessage, status int) any {
	if status != 0 {
		return map[string]any{"_unobserved": status}
	}
	return rawArray(items)
}

func writeListOrMark(cp engine.CurrentPhase, rel, collector, sourcePath string, items []json.RawMessage, status int) error {
	return envelope(cp, rel, collector, sourcePath, listOrMark(items, status))
}

// softGet returns (raw, status): status is 0 on success, or the soft HTTP code
// (401/403/404) when the resource was unobservable (raw nil). A non-soft error
// propagates.
func softGet(ctx context.Context, cl GitLab, p string, params url.Values) (json.RawMessage, int, error) {
	raw, _, err := cl.Get(ctx, p, params, true)
	if err != nil {
		if isSoft(err) {
			return nil, softStatus(err), nil
		}
		return nil, 0, err
	}
	if raw == nil {
		return nil, 404, nil
	}
	return raw, 0, nil
}

func softList(ctx context.Context, cl GitLab, p string, params url.Values) ([]json.RawMessage, int, error) {
	items, err := cl.Paginate(ctx, p, params)
	if err != nil {
		if isSoft(err) {
			return nil, softStatus(err), nil
		}
		return nil, 0, err
	}
	return items, 0, nil
}

// graphQLSoft posts a query and returns the raw `data` object, or a soft status
// (403) when the response carries a FORBIDDEN error, so a permission-denied
// GraphQL surface marks _unobserved instead of aborting.
func graphQLSoft(ctx context.Context, cl GitLab, query string, vars map[string]any) (json.RawMessage, int, error) {
	raw, err := cl.GraphQL(ctx, query, vars)
	if err != nil {
		if isSoft(err) {
			return nil, softStatus(err), nil
		}
		return nil, 0, err
	}
	var env struct {
		Data   json.RawMessage `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if json.Unmarshal(raw, &env) != nil {
		return raw, 0, nil
	}
	if len(env.Errors) > 0 && env.Data == nil {
		return nil, 403, nil
	}
	return env.Data, 0, nil
}
