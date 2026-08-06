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

// A soft-failed surface is written as a {"_unobserved":<status>} marker so downstream
// can tell "no access" from "never collected".
func writeOrMark(cp engine.CurrentPhase, rel, collector, sourcePath string, raw json.RawMessage, status int) error {
	if status != 0 {
		return envelope(cp, rel, collector, sourcePath, map[string]any{"_unobserved": status})
	}
	return envelope(cp, rel, collector, sourcePath, raw)
}

// Never nil on success, and a marker on a soft failure, so a forbidden list never
// reads as "none exist".
func listOrMark(items []json.RawMessage, status int) any {
	if status != 0 {
		return map[string]any{"_unobserved": status}
	}
	return rawArray(items)
}

func writeListOrMark(cp engine.CurrentPhase, rel, collector, sourcePath string, items []json.RawMessage, status int) error {
	return envelope(cp, rel, collector, sourcePath, listOrMark(items, status))
}

// status is 0 on success, or the soft HTTP code when the resource was unobservable
// (raw nil). A non-soft error propagates.
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

// GraphQL answers 200 with an errors array rather than an HTTP status, so a response
// carrying errors and no data is reported as a soft 403 and marks _unobserved.
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
