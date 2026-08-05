package ado

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"net/url"
)

// Pages are followed via the x-ms-continuationtoken response header, resent as the
// continuationToken query param. A single-object response comes back as one element
// so callers stay uniform.
func (c *Client) Paginate(ctx context.Context, host, api, path string, params url.Values) ([]json.RawMessage, error) {
	p := maps.Clone(params)
	if p == nil {
		p = url.Values{}
	}
	var items []json.RawMessage
	prevCont := ""
	// The page cap backstops a server returning an unchanging continuation token,
	// which would otherwise loop forever; 10k pages far exceeds any real list.
	for page := 0; page < 10000; page++ {
		raw, hdr, err := c.Get(ctx, host, api, path, p, false)
		if err != nil {
			return nil, err
		}
		// A {count,value} list envelope has BOTH keys; require value present so a
		// detail object that merely carries a "count" field isn't misread as a list.
		var env struct {
			Count *int              `json:"count"`
			Value []json.RawMessage `json:"value"`
		}
		if err := json.Unmarshal(raw, &env); err == nil && env.Count != nil && env.Value != nil {
			items = append(items, env.Value...)
		} else {
			items = append(items, raw)
			return items, nil
		}
		cont := hdr.Get("x-ms-continuationtoken")
		if cont == "" || cont == prevCont {
			break
		}
		prevCont = cont
		p.Set("continuationToken", cont)
	}
	return items, nil
}

func softStatus(err error) int {
	var adoErr *AdoError
	if errors.As(err, &adoErr) {
		return adoErr.Status
	}
	return 0
}

// A soft failure skips and marks an optional surface instead of aborting the phase.
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
