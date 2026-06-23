package github

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// graphqlEndpoint is a var (not const) so tests can repoint it at an httptest
// server, mirroring apiBase for the REST client.
var graphqlEndpoint = "https://api.github.com/graphql"

// gqlError is one entry of a GraphQL response's top-level "errors" array.
type gqlError struct {
	Type    string `json:"type"`
	Message string `json:"message"`
}

// gqlEnvelope is the standard GraphQL response shape: data + optional errors.
type gqlEnvelope struct {
	Data   json.RawMessage `json:"data"`
	Errors []gqlError      `json:"errors"`
}

// gqlClient issues hand-rolled POST /graphql queries on the existing REST
// Client's http transport (bearer auth is set by authTransport). It reuses the
// REST client's rate-limit backoff (sleepForRateLimit) so a throttled GraphQL
// call retries on Retry-After/x-ratelimit-reset like the REST path; an exhausted
// budget surfaces a *GhError the router treats as transient and falls through on.
type gqlClient struct {
	c *Client
}

// query runs a GraphQL query with vars and unmarshals data into out. A transport
// error or a GraphQL "errors" payload becomes a *GhError so the router and
// collectors handle it identically to a REST failure (NOT_FOUND/FORBIDDEN map to
// 404/403 soft-fails; everything else is surfaced).
func (g *gqlClient) query(ctx context.Context, query string, vars map[string]any, out any) error {
	body, err := json.Marshal(map[string]any{"query": query, "variables": vars})
	if err != nil {
		return err
	}
	for i := 0; i < 6; i++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, graphqlEndpoint, bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := g.c.http.Do(req)
		if err != nil {
			return err
		}
		if resp.StatusCode == http.StatusOK {
			raw := readAllClose(resp)
			var env gqlEnvelope
			if uerr := json.Unmarshal(raw, &env); uerr != nil {
				return &GhError{Status: 200, URL: graphqlEndpoint, Body: "graphql: " + uerr.Error()}
			}
			if len(env.Errors) > 0 {
				return gqlErrorsToGhError(env.Errors)
			}
			if out == nil {
				return nil
			}
			return json.Unmarshal(env.Data, out)
		}
		switch {
		case resp.StatusCode == 502 || resp.StatusCode == 503 || resp.StatusCode == 504:
			b := readAllClose(resp)
			sleepFn(ctx, 2)
			if i == 5 {
				return &GhError{Status: resp.StatusCode, URL: graphqlEndpoint, Body: string(b)}
			}
		default:
			if g.c.sleepForRateLimit(ctx, resp) {
				readAllClose(resp)
				continue
			}
			b := readAllClose(resp)
			return &GhError{Status: resp.StatusCode, URL: graphqlEndpoint, Body: string(b)}
		}
	}
	return &GhError{Status: 0, URL: graphqlEndpoint, Body: "graphql: retries exhausted"}
}

// gqlErrorsToGhError collapses a GraphQL errors array into the *GhError shape the
// collectors soft-degrade on: NOT_FOUND -> 404, FORBIDDEN -> 403, else a generic
// failure (status 0) the router treats as transient (fall through to REST).
func gqlErrorsToGhError(errs []gqlError) *GhError {
	status := 0
	for _, e := range errs {
		switch e.Type {
		case "NOT_FOUND":
			status = 404
		case "FORBIDDEN", "INSUFFICIENT_SCOPES":
			if status == 0 {
				status = 403
			}
		}
	}
	b, _ := json.Marshal(errs)
	return &GhError{Status: status, URL: graphqlEndpoint, Body: "graphql errors: " + string(b)}
}

// jsonNum renders an integer as a raw JSON number, or null for absent (matching
// REST numeric ids serialized without quotes).
func jsonNum(n *int64) json.RawMessage {
	if n == nil {
		return json.RawMessage("null")
	}
	return json.RawMessage(fmt.Sprintf("%d", *n))
}
