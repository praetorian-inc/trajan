package ado

import (
	"encoding/json"
	"strconv"

	"github.com/praetorian-inc/trajan/internal/engine"
)

// Normalize-side helpers, ported from the GitHub stack (platform-agnostic): safe
// navigation over the collected {_meta,data} envelopes, and reading the
// normalized corpus back as generic maps for the correlate pass.

// entLoadData returns the "data" object of a collected envelope, or nil for a
// missing file / null data (so callers skip the surface).
func entLoadData(prior engine.PriorPhase, rel string) map[string]any {
	var env map[string]any
	if err := engine.ReadJSON(prior.Abs(rel), &env); err != nil {
		return nil
	}
	return entMap(env["data"])
}

// entLoadList returns the "data" of a list-surface envelope as []any (the ADO
// list endpoints store the value array directly under data).
func entLoadList(prior engine.PriorPhase, rel string) []any {
	var env map[string]any
	if err := engine.ReadJSON(prior.Abs(rel), &env); err != nil {
		return nil
	}
	return entList(env["data"])
}

// entDataOf returns the "data" object of a collected envelope (nil for a
// non-object body such as a bare list surface — callers reading those use
// entLoadList instead).
func entDataOf(b []byte) map[string]any {
	var env map[string]any
	if err := json.Unmarshal(b, &env); err != nil {
		return nil
	}
	return entMap(env["data"])
}

func entMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func entList(v any) []any {
	l, _ := v.([]any)
	return l
}

// entListOrEmpty never returns nil so a list field serializes as [] not null.
func entListOrEmpty(v any) []any {
	if l, ok := v.([]any); ok {
		return l
	}
	return []any{}
}

// entObj never returns nil so chained indexing is safe.
func entObj(m map[string]any, key string) map[string]any {
	if o := entMap(m[key]); o != nil {
		return o
	}
	return map[string]any{}
}

func entGetIn(m map[string]any, keys ...string) any {
	var cur any = m
	for _, k := range keys {
		cm := entMap(cur)
		if cm == nil {
			return nil
		}
		cur = cm[k]
	}
	return cur
}

func entStr(v any) string {
	s, _ := v.(string)
	return s
}

func entBool(v any) bool {
	b, _ := v.(bool)
	return b
}

func entInt64(v any) int64 {
	switch x := v.(type) {
	case float64:
		return int64(x)
	case int:
		return int64(x)
	case int64:
		return x
	case string:
		if n, err := strconv.ParseInt(x, 10, 64); err == nil {
			return n
		}
	case json.Number:
		if n, err := x.Int64(); err == nil {
			return n
		}
	}
	return 0
}

// ---- correlate read-side (normalized corpus as maps) ----

func loadRecords(prior engine.PriorPhase, dir string) ([]map[string]any, error) {
	files, err := prior.IterJSON(dir)
	if err != nil {
		return nil, err
	}
	out := make([]map[string]any, 0, len(files))
	for _, f := range files {
		var rec map[string]any
		if err := json.Unmarshal(f.Data, &rec); err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, nil
}

func mGet(m map[string]any, key string) any {
	if m == nil {
		return nil
	}
	return m[key]
}

func mStr(m map[string]any, key string) string {
	s, _ := mGet(m, key).(string)
	return s
}

func mBool(m map[string]any, key string) bool {
	b, _ := mGet(m, key).(bool)
	return b
}

func mMap(m map[string]any, key string) map[string]any {
	v, _ := mGet(m, key).(map[string]any)
	return v
}

func mList(m map[string]any, key string) []any {
	v, _ := mGet(m, key).([]any)
	return v
}

func mInt64(m map[string]any, key string) int64 {
	return entInt64(mGet(m, key))
}

type provenance struct {
	File string `json:"file"`
}

func prov(files ...string) []provenance {
	out := make([]provenance, 0, len(files))
	for _, f := range files {
		out = append(out, provenance{File: f})
	}
	return out
}
