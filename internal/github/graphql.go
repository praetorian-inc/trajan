package github

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// var not const so tests can repoint it at an httptest server, mirroring apiBase
var graphqlEndpoint = "https://api.github.com/graphql"

type gqlError struct {
	Type    string `json:"type"`
	Message string `json:"message"`
}

type gqlEnvelope struct {
	Data   json.RawMessage `json:"data"`
	Errors []gqlError      `json:"errors"`
}

// Issues POST /graphql on the REST Client's http transport, so authTransport sets
// bearer auth and sleepForRateLimit governs throttling as it does on the REST path.
// An exhausted budget surfaces a *GhError the router treats as transient.
type gqlClient struct {
	c *Client
}

// A GraphQL "errors" payload becomes a *GhError so the router and collectors handle
// it identically to a REST failure.
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
			raw, _ := readAllClose(resp)
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
		switch resp.StatusCode {
		case 502, 503, 504:
			b, _ := readAllClose(resp)
			sleepFn(ctx, 2)
			if i == 5 {
				return &GhError{Status: resp.StatusCode, URL: graphqlEndpoint, Body: string(b)}
			}
		default:
			b, _ := readAllClose(resp)
			if g.c.sleepForRateLimit(ctx, resp, b, i) {
				continue
			}
			return &GhError{Status: resp.StatusCode, URL: graphqlEndpoint, Body: string(b)}
		}
	}
	return &GhError{Status: 0, URL: graphqlEndpoint, Body: "graphql: retries exhausted"}
}

// Collapses the errors array into the *GhError shape collectors soft-degrade on:
// NOT_FOUND -> 404, FORBIDDEN -> 403, else status 0, which the router treats as
// transient and falls through to REST on.
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

// A raw JSON number (null when absent), matching REST ids serialized unquoted.
func jsonNum(n *int64) json.RawMessage {
	if n == nil {
		return json.RawMessage("null")
	}
	return json.RawMessage(fmt.Sprintf("%d", *n))
}
