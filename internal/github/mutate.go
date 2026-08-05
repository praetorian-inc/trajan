package github

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// ErrAmbiguous marks a mutation whose outcome is unknown: the request reached
// GitHub and came back 5xx, so the change may or may not have landed. The caller
// must read back to establish which before re-issuing.
var ErrAmbiguous = errors.New("mutation outcome unknown")

// Mutator is the write half of the client, kept apart from GitHub (the read
// interface) so a collector can be handed a client that cannot mutate.
type Mutator interface {
	Mutate(ctx context.Context, method, pathOrURL string, body any) (json.RawMessage, int, error)
}

var _ Mutator = (*Client)(nil)

// One non-idempotent request. Unlike Get's six-iteration loop it retries at most
// once, and only on a rejection that provably did not apply — a secondary- or
// primary-limit 403/429 the client slept for. A 5xx is never retried: a retried
// POST /pulls opens two pull requests.
func (c *Client) Mutate(ctx context.Context, method, pathOrURL string, body any) (json.RawMessage, int, error) {
	u := resolveURL(pathOrURL)
	var payload []byte
	if body != nil {
		var err error
		payload, err = json.Marshal(body)
		if err != nil {
			return nil, 0, fmt.Errorf("encode %s %s body: %w", method, u, err)
		}
	}

	retried := false
	for {
		var rdr io.Reader
		if payload != nil {
			rdr = bytes.NewReader(payload)
		}
		resp, err := c.do(ctx, method, u, nil, "", rdr)
		if err != nil {
			return nil, 0, err
		}
		status := resp.StatusCode
		b, rerr := readAllClose(resp)
		switch {
		case status >= 200 && status < 300:
			if rerr != nil {
				return nil, status, fmt.Errorf("read response body from %s: %w", u, rerr)
			}
			return json.RawMessage(b), status, nil
		case status >= 500:
			return nil, status, fmt.Errorf("%w: %w", ErrAmbiguous, &GhError{Status: status, URL: u, Body: string(b)})
		case !retried && c.sleepForRateLimit(ctx, resp, b, 0):
			retried = true
		default:
			return nil, status, &GhError{Status: status, URL: u, Body: string(b)}
		}
	}
}
