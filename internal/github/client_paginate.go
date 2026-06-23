package github

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"maps"
	"net/url"
	"strconv"
	"strings"
)

func (c *Client) Paginate(ctx context.Context, path string, params url.Values, perPage int) ([]json.RawMessage, error) {
	return c.paginateFrom(ctx, apiBase+path, params, perPage)
}

// firstURL is absolute; subsequent requests follow Link rel="next" verbatim
func (c *Client) paginateFrom(ctx context.Context, firstURL string, params url.Values, perPage int) ([]json.RawMessage, error) {
	if perPage <= 0 {
		perPage = 100
	}
	p := maps.Clone(params)
	if p == nil {
		p = url.Values{}
	}
	if p.Get("per_page") == "" {
		p.Set("per_page", strconv.Itoa(perPage))
	}

	var items []json.RawMessage
	u := firstURL
	sendParams := p
	for u != "" {
		raw, headers, err := c.Get(ctx, u, sendParams, false)
		if err != nil {
			return nil, err
		}
		trimmed := strings.TrimLeft(string(raw), " \t\r\n")
		switch {
		case strings.HasPrefix(trimmed, "["):
			var arr []json.RawMessage
			if err := json.Unmarshal(raw, &arr); err != nil {
				return nil, err
			}
			items = append(items, arr...)
		case strings.HasPrefix(trimmed, "{"):
			var obj map[string]json.RawMessage
			if err := json.Unmarshal(raw, &obj); err != nil {
				return nil, err
			}
			if v, ok := obj["items"]; ok {
				var arr []json.RawMessage
				if err := json.Unmarshal(v, &arr); err != nil {
					return nil, err
				}
				items = append(items, arr...)
			} else if _, ok := obj["total_count"]; ok {
				// map range order is non-deterministic, but these envelopes carry
				// exactly one list key, so break-on-first is unambiguous
				for k, v := range obj {
					if k == "total_count" || k == "repository_selection" {
						continue
					}
					if vt := strings.TrimLeft(string(v), " \t\r\n"); strings.HasPrefix(vt, "[") {
						var arr []json.RawMessage
						if err := json.Unmarshal(v, &arr); err != nil {
							return nil, err
						}
						items = append(items, arr...)
						break
					}
				}
			} else {
				items = append(items, raw)
				return items, nil
			}
		default:
			items = append(items, raw)
			return items, nil
		}
		u = nextLink(headers.Get("Link"))
		sendParams = nil
	}
	return items, nil
}

func nextLink(linkHeader string) string {
	if linkHeader == "" {
		return ""
	}
	for _, part := range strings.Split(linkHeader, ",") {
		seg := strings.TrimSpace(part)
		if strings.Contains(seg, `rel="next"`) {
			start := strings.Index(seg, "<")
			end := strings.Index(seg, ">")
			if start != -1 && end != -1 && end > start {
				return seg[start+1 : end]
			}
		}
	}
	return ""
}

func decodeString(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return ""
	}
	return s
}

// GitHub returns Contents-API base64 with embedded newlines, so strip whitespace first
func base64Decode(s string) ([]byte, error) {
	cleaned := strings.NewReplacer("\n", "", "\r", "", " ", "").Replace(s)
	return base64.StdEncoding.DecodeString(cleaned)
}

func asGhError(err error, target **GhError) bool {
	return errors.As(err, target)
}

// percent-encodes a ref path while keeping "/" literal (urllib quote(safe="/"))
func quoteKeepSlash(ref string) string {
	var b strings.Builder
	for i := 0; i < len(ref); i++ {
		c := ref[i]
		if c == '/' || isUnreservedQuoteByte(c) {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(upperHex(c >> 4))
		b.WriteByte(upperHex(c & 0x0f))
	}
	return b.String()
}

// RFC 3986 unreserved: ALPHA / DIGIT / - . _ ~
func isUnreservedQuoteByte(c byte) bool {
	switch {
	case c >= 'A' && c <= 'Z':
		return true
	case c >= 'a' && c <= 'z':
		return true
	case c >= '0' && c <= '9':
		return true
	case c == '-' || c == '.' || c == '_' || c == '~':
		return true
	}
	return false
}

func upperHex(n byte) byte {
	const hex = "0123456789ABCDEF"
	return hex[n&0x0f]
}
