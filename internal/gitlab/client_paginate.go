package gitlab

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/url"
)

// Paginate follows GitLab's X-Next-Page header, accumulating each page's array
// into one raw slice. per_page=100. A non-array body is returned as a single
// element so callers stay uniform.
func (c *Client) Paginate(ctx context.Context, p string, params url.Values) ([]json.RawMessage, error) {
	q := maps.Clone(params)
	if q == nil {
		q = url.Values{}
	}
	q.Set("per_page", "100")
	var items []json.RawMessage
	page := 1
	// Page cap backstops a server whose X-Next-Page never advances.
	for i := 0; i < 10000; i++ {
		q.Set("page", fmt.Sprintf("%d", page))
		raw, hdr, err := c.Get(ctx, p, q, false)
		if err != nil {
			return nil, err
		}
		var arr []json.RawMessage
		if err := json.Unmarshal(raw, &arr); err != nil {
			items = append(items, raw)
			return items, nil
		}
		items = append(items, arr...)
		next := hdr.Get("X-Next-Page")
		if next == "" {
			break
		}
		var nextNum int
		if _, err := fmt.Sscanf(next, "%d", &nextNum); err != nil || nextNum <= page {
			break
		}
		page = nextNum
	}
	return items, nil
}

func softStatus(err error) int {
	var glErr *GitLabError
	if errors.As(err, &glErr) {
		return glErr.Status
	}
	return 0
}

// isSoft reports an optional-surface failure that should skip-and-mark rather
// than abort: 401/403 (permission) or 404 (absent).
func isSoft(err error) bool {
	switch softStatus(err) {
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
		return true
	}
	return false
}

func decodeString(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return ""
	}
	return s
}

func objField(raw json.RawMessage, key string) json.RawMessage {
	if len(raw) == 0 {
		return nil
	}
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil {
		return nil
	}
	return m[key]
}

func strField(raw json.RawMessage, key string) string {
	return decodeString(objField(raw, key))
}

func numField(raw json.RawMessage, key string) int64 {
	v := objField(raw, key)
	if len(v) == 0 {
		return 0
	}
	var n int64
	if json.Unmarshal(v, &n) != nil {
		return 0
	}
	return n
}

// rawArray ensures a nil slice marshals as [] (rules key on it).
func rawArray(items []json.RawMessage) []json.RawMessage {
	if items == nil {
		return []json.RawMessage{}
	}
	return items
}
