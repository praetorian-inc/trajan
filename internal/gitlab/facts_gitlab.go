package gitlab

import (
	"encoding/json"
	"os"
	"strconv"
	"strings"

	"github.com/praetorian-inc/trajan/internal/engine"
)

// Normalize-side read helpers, ported from the ADO/GitHub stacks (platform
// agnostic): safe navigation over the collected {_meta,data} envelopes, raw-file
// reads, and reading the normalized corpus back as generic maps for correlate.
//
// A soft-failed surface is written as data == {"_unobserved": <status>}. The
// unwrap helpers return that object verbatim so a caller can distinguish "observed
// empty" from "not observed" (entUnobserved) rather than collapsing to false/[].

func entLoadData(prior engine.PriorPhase, rel string) map[string]any {
	var env map[string]any
	if err := engine.ReadJSON(prior.Abs(rel), &env); err != nil {
		return nil
	}
	return entMap(env["data"])
}

// entLoadList returns the data array of a list surface, or nil for a missing file
// / soft-failed surface (whose data is a {_unobserved} object, not an array).
func entLoadList(prior engine.PriorPhase, rel string) []any {
	var env map[string]any
	if err := engine.ReadJSON(prior.Abs(rel), &env); err != nil {
		return nil
	}
	return entList(env["data"])
}

// entLoadRaw reads a non-enveloped raw file (.gitlab-ci.yml, agent config,
// CODEOWNERS, Duo files) written via WriteRaw. nil for a missing file.
func entLoadRaw(prior engine.PriorPhase, rel string) []byte {
	b, err := os.ReadFile(prior.Abs(rel))
	if err != nil {
		return nil
	}
	return b
}

// entUnobserved reports whether a surface soft-failed (data == {_unobserved}).
// A rule that keys on the observed/unobserved difference must not read absence as
// false; callers use this to leave the field null instead.
func entUnobserved(m map[string]any) bool {
	if m == nil {
		return false
	}
	_, un := m["_unobserved"]
	return un
}

func entMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func entList(v any) []any {
	l, _ := v.([]any)
	return l
}

// entListOrEmpty never returns nil so a list field serializes as [] not null
// (hard contract C1: valuesEqual(nil, []any{}) is false).
func entListOrEmpty(v any) []any {
	if l, ok := v.([]any); ok {
		return l
	}
	return []any{}
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

func mStr(m map[string]any, key string) string { s, _ := mGet(m, key).(string); return s }
func mBool(m map[string]any, key string) bool  { b, _ := mGet(m, key).(bool); return b }
func mMap(m map[string]any, key string) map[string]any {
	v, _ := mGet(m, key).(map[string]any)
	return v
}
func mList(m map[string]any, key string) []any { v, _ := mGet(m, key).([]any); return v }

type provenance map[string]string

func prov(files ...string) []provenance {
	out := make([]provenance, 0, len(files))
	for _, f := range files {
		out = append(out, provenance{"file": f})
	}
	return out
}

// ---- GitLab-specific fact helpers ----

// GitLab numeric access levels. Rules read >=30, ∋{30}, ==30 (hard contract C3).
const (
	accessGuest      int64 = 10
	accessReporter   int64 = 20
	accessDeveloper  int64 = 30
	accessMaintainer int64 = 40
	accessOwner      int64 = 50
)

var levelNames = map[int64]string{
	accessGuest: "guest", accessReporter: "reporter", accessDeveloper: "developer",
	accessMaintainer: "maintainer", accessOwner: "owner",
}
var nameLevels = map[string]int64{
	"guest": accessGuest, "reporter": accessReporter, "developer": accessDeveloper,
	"maintainer": accessMaintainer, "owner": accessOwner,
}

func levelToRoleName(lvl int64) string { return levelNames[lvl] }

// roleNameToLevel maps a group default_membership_role that GitLab may return
// either as the numeric access level (REST) or the string enum.
func roleNameToLevel(v any) int64 {
	switch x := v.(type) {
	case string:
		if n, ok := nameLevels[strings.ToLower(x)]; ok {
			return n
		}
		return entInt64(x)
	default:
		return entInt64(v)
	}
}

// accessLevelValues extracts the numeric access_level from a protected-branch /
// protected-tag access-level list ([{access_level, group_id, user_id, ...}]). A
// group/user entry (non-null group_id/user_id) is a named grant broader than the
// bare role; it is surfaced as its numeric level and flagged by hasNamedGrant.
func accessLevelValues(list any) []any {
	out := []any{}
	for _, raw := range entList(list) {
		e := entMap(raw)
		out = append(out, entInt64(e["access_level"]))
	}
	return out
}

func hasNamedGrant(list any) bool {
	for _, raw := range entList(list) {
		e := entMap(raw)
		if e["group_id"] != nil || e["user_id"] != nil {
			return true
		}
	}
	return false
}

// levelsInclude reports whether a numeric access-level list contains lvl.
func levelsInclude(levels []any, lvl int64) bool {
	for _, v := range levels {
		if entInt64(v) == lvl {
			return true
		}
	}
	return false
}

// levelsIncludeAtMost reports whether the list grants access to any actor at or
// below maxLvl (i.e. a lower-trust actor than a strict Maintainer/Owner gate).
func levelsIncludeAtMost(levels []any, maxLvl int64) bool {
	for _, v := range levels {
		if l := entInt64(v); l > 0 && l <= maxLvl {
			return true
		}
	}
	return false
}

// hasMemberAtLevel precomputes an existential over a members list (hard contract
// C4): ∃ member with access_level == lvl. The engine's ∋ cannot express this.
func hasMemberAtLevel(members []any, lvl int64) bool {
	for _, raw := range members {
		if entInt64(entMap(raw)["access_level"]) == lvl {
			return true
		}
	}
	return false
}

// secretShapedKey is the secret-name heuristic (cat-03/11). The three
// unprotected-secret-var derived booleans rest entirely on it, so it must not
// fire on ordinary config keys. Matches common credential-bearing key fragments.
func secretShapedKey(key string) bool {
	u := strings.ToUpper(key)
	for _, frag := range []string{
		"TOKEN", "SECRET", "PASSWORD", "PASSWD", "APIKEY", "API_KEY", "ACCESS_KEY",
		"PRIVATE_KEY", "CREDENTIAL", "AUTH", "PAT", "KEY", "CERT", "SIGNING",
		"AWS_", "AZURE_", "GCP_", "GCLOUD", "DOCKERHUB", "NPM_", "PYPI",
	} {
		if strings.Contains(u, frag) {
			return true
		}
	}
	return false
}
