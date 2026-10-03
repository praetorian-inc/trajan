//go:build js

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall/js"

	"github.com/praetorian-inc/trajan/internal/ado"
	"github.com/praetorian-inc/trajan/internal/engine"
	"github.com/praetorian-inc/trajan/internal/github"
	"github.com/praetorian-inc/trajan/internal/gitlab"
	"github.com/praetorian-inc/trajan/internal/report"
	"github.com/praetorian-inc/trajan/internal/ui"
)

var (
	cfg           = &engine.Config{Concurrency: 8, OutputDir: "/run"}
	activeCancel  context.CancelFunc
	onLogCallback js.Value
	initialized   bool
)

func registerAPI() {
	js.Global().Set("trajanInitialize", js.FuncOf(promiseOf(initialize)))
	js.Global().Set("trajanWhoAmI", js.FuncOf(promiseOf(whoami)))
	js.Global().Set("trajanScan", js.FuncOf(promiseOf(scan)))
	js.Global().Set("trajanReport", js.FuncOf(promiseOf(reportFn)))
	js.Global().Set("trajanCancel", js.FuncOf(cancel))
	js.Global().Set("trajanVersion", js.FuncOf(func(this js.Value, args []js.Value) any {
		return map[string]any{
			"version":   Version,
			"buildTime": BuildTime,
			"gitCommit": GitCommit,
		}
	}))
}

// promiseOf wraps a Go handler so JS gets a Promise. Work runs in a goroutine;
// a blocking js.FuncOf would deadlock browser fetch.
func promiseOf(fn func(js.Value) (any, error)) func(js.Value, []js.Value) any {
	return func(this js.Value, args []js.Value) any {
		var opts js.Value
		if len(args) > 0 {
			opts = args[0]
		} else {
			opts = js.Null()
		}
		handler := js.FuncOf(func(this js.Value, args []js.Value) any {
			resolve := args[0]
			reject := args[1]
			go func() {
				defer func() {
					if r := recover(); r != nil {
						reject.Invoke(jsError(fmt.Errorf("panic: %v", r)))
					}
				}()
				out, err := fn(opts)
				if err != nil {
					reject.Invoke(jsError(err))
					return
				}
				resolve.Invoke(toJS(out))
			}()
			return nil
		})
		return js.Global().Get("Promise").New(handler)
	}
}

func jsError(err error) map[string]any {
	return map[string]any{"error": err.Error()}
}

func toJS(v any) any {
	if v == nil {
		return js.Null()
	}
	switch x := v.(type) {
	case map[string]any:
		return x
	case string, bool, float64, int, int64:
		return x
	default:
		b, err := json.Marshal(x)
		if err != nil {
			return map[string]any{"error": err.Error()}
		}
		var m any
		if err := json.Unmarshal(b, &m); err != nil {
			return string(b)
		}
		return convertJSON(m)
	}
}

func convertJSON(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := map[string]any{}
		for k, val := range x {
			out[k] = convertJSON(val)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, val := range x {
			out[i] = convertJSON(val)
		}
		return out
	case float64, string, bool, nil:
		return x
	default:
		return fmt.Sprint(x)
	}
}

func strOpt(opts js.Value, key, fallback string) string {
	if opts.IsNull() || opts.IsUndefined() {
		return fallback
	}
	v := opts.Get(key)
	if v.IsUndefined() || v.IsNull() {
		return fallback
	}
	return v.String()
}

func intOpt(opts js.Value, key string, fallback int) int {
	if opts.IsNull() || opts.IsUndefined() {
		return fallback
	}
	v := opts.Get(key)
	if v.IsUndefined() || v.IsNull() {
		return fallback
	}
	n := v.Int()
	if n <= 0 {
		return fallback
	}
	return n
}

func boolOpt(opts js.Value, key string) bool {
	if opts.IsNull() || opts.IsUndefined() {
		return false
	}
	v := opts.Get(key)
	return !v.IsUndefined() && !v.IsNull() && v.Bool()
}

type jsLogHandler struct{}

func (h *jsLogHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *jsLogHandler) Handle(_ context.Context, r slog.Record) error {
	if onLogCallback.IsUndefined() || onLogCallback.IsNull() {
		return nil
	}
	attrs := map[string]any{}
	r.Attrs(func(a slog.Attr) bool {
		attrs[a.Key] = a.Value.String()
		return true
	})
	onLogCallback.Invoke(r.Level.String(), r.Message, attrs)
	return nil
}

func (h *jsLogHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *jsLogHandler) WithGroup(string) slog.Handler      { return h }

func initialize(opts js.Value) (any, error) {
	ui.Init(ui.Human, false)
	slog.SetDefault(slog.New(&jsLogHandler{}))

	cfg.OutputDir = strOpt(opts, "outputDir", "/run")
	if !strings.HasPrefix(cfg.OutputDir, "/") {
		return nil, fmt.Errorf("outputDir must be absolute (browser has no working directory); got %q", cfg.OutputDir)
	}
	cfg.Concurrency = intOpt(opts, "concurrency", 8)

	cb := opts.Get("onLog")
	if !cb.IsUndefined() && !cb.IsNull() && cb.Type() == js.TypeFunction {
		onLogCallback = cb
	} else {
		onLogCallback = js.Undefined()
	}

	if err := os.MkdirAll(cfg.OutputDir, 0o755); err != nil {
		return nil, fmt.Errorf("mkdir outputDir: %w", err)
	}
	initialized = true
	return map[string]any{
		"ok":          true,
		"outputDir":   cfg.OutputDir,
		"concurrency": cfg.Concurrency,
		"version":     Version,
	}, nil
}

func normalizePlatform(p string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(p)) {
	case "github", "gh":
		return "github", nil
	case "gitlab", "gl":
		return "gitlab", nil
	case "ado", "azuredevops", "azure-devops", "azdo":
		return "ado", nil
	default:
		return "", fmt.Errorf("unsupported platform %q (want github|gitlab|ado)", p)
	}
}

func applyGitLabBase(baseURL string) error {
	baseURL = strings.TrimSpace(baseURL)
	if baseURL == "" {
		gitlab.FlagURL = "https://gitlab.com"
		return nil
	}
	if err := validateHTTPURL(baseURL); err != nil {
		return err
	}
	gitlab.FlagURL = baseURL
	return nil
}

func validateHTTPURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("unsupported URL scheme %q", u.Scheme)
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return fmt.Errorf("URL must include a hostname")
	}
	blocked := []string{"169.254.169.254", "169.254.169.253", "metadata.google.internal", "metadata.azure.com"}
	for _, b := range blocked {
		if host == b || strings.Contains(host, b) {
			return fmt.Errorf("access to cloud metadata service is forbidden")
		}
	}
	return nil
}

func whoami(opts js.Value) (any, error) {
	if !initialized {
		return nil, fmt.Errorf("call initialize first")
	}
	platform, err := normalizePlatform(strOpt(opts, "platform", ""))
	if err != nil {
		return nil, err
	}
	token := strOpt(opts, "token", "")
	baseURL := strOpt(opts, "baseUrl", "")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	switch platform {
	case "github":
		return githubIdentity(ctx, token)
	case "gitlab":
		if err := applyGitLabBase(baseURL); err != nil {
			return nil, err
		}
		if gitlab.FlagInsecure {
			return nil, fmt.Errorf("GitLab insecure TLS is not supported in the browser (fetch ignores InsecureSkipVerify)")
		}
		return gitlabIdentity(ctx, token)
	case "ado":
		org := strOpt(opts, "org", "")
		if org == "" {
			org = strOpt(opts, "locator", "")
		}
		bearer := strOpt(opts, "bearerToken", "")
		return adoIdentity(ctx, org, token, bearer)
	}
	return nil, fmt.Errorf("unsupported platform")
}

func githubIdentity(ctx context.Context, token string) (any, error) {
	tok, err := github.ResolveToken(ctx, token)
	if err != nil {
		return nil, err
	}
	c := github.NewClient(tok)
	if raw, hdr, err := c.Get(ctx, "/user", nil, false); err == nil {
		var user struct {
			Login string `json:"login"`
			ID    int64  `json:"id"`
		}
		if err := json.Unmarshal(raw, &user); err != nil {
			return nil, err
		}
		return map[string]any{
			"platform": "github",
			"kind":     "user",
			"login":    user.Login,
			"id":       float64(user.ID),
			"scopes":   hdr.Get("X-OAuth-Scopes"),
		}, nil
	}
	raw, _, err := c.Get(ctx, "/installation/repositories", url.Values{"per_page": []string{"1"}}, false)
	if err != nil {
		return nil, fmt.Errorf("token is not a user token and /installation/repositories failed: %w", err)
	}
	var inst struct {
		TotalCount int `json:"total_count"`
	}
	if err := json.Unmarshal(raw, &inst); err != nil {
		return nil, err
	}
	return map[string]any{
		"platform":               "github",
		"kind":                   "app",
		"accessibleRepositories": float64(inst.TotalCount),
	}, nil
}

func gitlabIdentity(ctx context.Context, token string) (any, error) {
	tok, err := gitlab.ResolveToken(token)
	if err != nil {
		return nil, err
	}
	cl := gitlab.NewClient(gitlab.ResolveBaseURL(gitlab.FlagURL), tok, false, 1)
	userRaw, _, err := cl.Get(ctx, "/user", nil, false)
	if err != nil {
		return nil, err
	}
	var user struct {
		Username string `json:"username"`
		Name     string `json:"name"`
		IsAdmin  bool   `json:"is_admin"`
		Bot      bool   `json:"bot"`
	}
	if err := json.Unmarshal(userRaw, &user); err != nil {
		return nil, err
	}
	out := map[string]any{
		"platform": "gitlab",
		"username": user.Username,
		"name":     user.Name,
		"admin":    user.IsAdmin,
		"bot":      user.Bot,
		"baseUrl":  gitlab.ResolveBaseURL(gitlab.FlagURL),
	}
	if patRaw, _, perr := cl.Get(ctx, "/personal_access_tokens/self", nil, true); perr == nil && patRaw != nil {
		var pat struct {
			Scopes []string `json:"scopes"`
		}
		if json.Unmarshal(patRaw, &pat) == nil {
			scopes := make([]any, len(pat.Scopes))
			for i, s := range pat.Scopes {
				scopes[i] = s
			}
			out["scopes"] = scopes
		}
	}
	return out, nil
}

func adoIdentity(ctx context.Context, org, pat, bearer string) (any, error) {
	if strings.TrimSpace(org) == "" {
		return nil, fmt.Errorf("ado whoami requires org (or locator)")
	}
	scope, err := ado.ParseScope(org)
	if err != nil {
		return nil, err
	}
	cred, err := ado.ResolveCredential(pat, bearer)
	if err != nil {
		return nil, err
	}
	var cl *ado.Client
	if cred.Kind == engine.CredBearer {
		cl = ado.NewClientBearer(scope.Org, cred.Value)
	} else {
		cl = ado.NewClient(scope.Org, cred.Value)
	}
	raw, _, err := cl.Get(ctx, "core", ado.APIVersionPreview, "/_apis/connectionData", nil, false)
	if err != nil {
		return nil, err
	}
	var conn struct {
		AuthenticatedUser struct {
			ID                  string `json:"id"`
			ProviderDisplayName string `json:"providerDisplayName"`
			Properties          struct {
				Account struct {
					Value string `json:"$value"`
				} `json:"Account"`
			} `json:"properties"`
		} `json:"authenticatedUser"`
		DeploymentType string `json:"deploymentType"`
	}
	if err := json.Unmarshal(raw, &conn); err != nil {
		return nil, err
	}
	u := conn.AuthenticatedUser
	identity := u.ProviderDisplayName
	if email := u.Properties.Account.Value; email != "" {
		identity += " <" + email + ">"
	}
	return map[string]any{
		"platform":       "ado",
		"identity":       identity,
		"id":             u.ID,
		"organization":   scope.Org,
		"deploymentType": conn.DeploymentType,
	}, nil
}

func scan(opts js.Value) (any, error) {
	if !initialized {
		return nil, fmt.Errorf("call initialize first")
	}
	platform, err := normalizePlatform(strOpt(opts, "platform", ""))
	if err != nil {
		return nil, err
	}
	locator := strings.TrimSpace(strOpt(opts, "locator", ""))
	existing := strings.TrimSpace(strOpt(opts, "runDir", ""))
	if locator == "" && existing == "" {
		return nil, fmt.Errorf("locator is required")
	}
	token := strOpt(opts, "token", "")
	bearer := strOpt(opts, "bearerToken", "")
	baseURL := strOpt(opts, "baseUrl", "")
	orgOnly := boolOpt(opts, "orgOnly")

	runCfg := &engine.Config{
		Concurrency: cfg.Concurrency,
		OutputDir:   cfg.OutputDir,
		Token:       token,
		BearerToken: bearer,
	}

	ctx, cancel := context.WithCancel(context.Background())
	activeCancel = cancel
	defer func() {
		cancel()
		activeCancel = nil
	}()

	var runDir string
	if existing != "" {
		// Scan-only over an already-normalized runDir (fixture / resume).
		runDir = existing
		switch platform {
		case "github":
			err = github.Scan(ctx, runDir, github.ScanOptions{OrgOnly: orgOnly})
		case "gitlab":
			if err := applyGitLabBase(baseURL); err != nil {
				return nil, err
			}
			err = gitlab.Scan(ctx, runDir, gitlab.ScanOptions{GroupOnly: orgOnly})
		case "ado":
			err = ado.Scan(ctx, runDir, ado.ScanOptions{OrgOnly: orgOnly})
		}
		if err != nil {
			return nil, err
		}
	} else {
		switch platform {
		case "github":
			runDir, err = github.Collect(ctx, runCfg, locator)
			if err != nil {
				return nil, err
			}
			if err := github.Normalize(ctx, runDir); err != nil {
				return nil, err
			}
			if err := github.Scan(ctx, runDir, github.ScanOptions{OrgOnly: orgOnly}); err != nil {
				return nil, err
			}
		case "gitlab":
			if err := applyGitLabBase(baseURL); err != nil {
				return nil, err
			}
			if gitlab.FlagInsecure {
				return nil, fmt.Errorf("GitLab insecure TLS is not supported in the browser")
			}
			runDir, err = gitlab.Collect(ctx, runCfg, locator)
			if err != nil {
				return nil, err
			}
			if err := gitlab.Normalize(ctx, runDir); err != nil {
				return nil, err
			}
			if err := gitlab.Scan(ctx, runDir, gitlab.ScanOptions{GroupOnly: orgOnly}); err != nil {
				return nil, err
			}
		case "ado":
			runDir, err = ado.Collect(ctx, runCfg, locator)
			if err != nil {
				return nil, err
			}
			if err := ado.Normalize(ctx, runDir); err != nil {
				return nil, err
			}
			if err := ado.Scan(ctx, runDir, ado.ScanOptions{OrgOnly: orgOnly}); err != nil {
				return nil, err
			}
		}
	}

	summary := map[string]any{
		"runDir":   runDir,
		"platform": platform,
		"locator":  locator,
	}
	if b, err := os.ReadFile(filepath.Join(runDir, "20-scan", "_summary.json")); err == nil {
		var s struct {
			RulesLoaded   int            `json:"rules_loaded"`
			TotalFindings int            `json:"total_findings"`
			RuleFires     map[string]int `json:"rule_fires"`
		}
		if json.Unmarshal(b, &s) == nil {
			summary["rulesLoaded"] = s.RulesLoaded
			summary["total"] = s.TotalFindings
			fires := map[string]any{}
			for k, v := range s.RuleFires {
				fires[k] = v
			}
			summary["ruleFires"] = fires
		}
	}
	if state, err := engine.LoadState(runDir); err == nil {
		degraded := 0
		bySev := map[string]any{}
		for _, p := range state.Phases {
			degraded += len(p.Errors)
		}
		summary["degraded"] = degraded
		// severity counts come from report meta; leave empty here if unknown
		summary["bySeverity"] = bySev
		_ = state
	}
	return summary, nil
}

func reportFn(opts js.Value) (any, error) {
	if !initialized {
		return nil, fmt.Errorf("call initialize first")
	}
	runDir := strOpt(opts, "runDir", "")
	if runDir == "" {
		return nil, fmt.Errorf("runDir is required")
	}
	format := strOpt(opts, "format", "html")
	ctx := context.Background()
	if err := report.Run(ctx, runDir, report.Options{
		Format:        format,
		MinSeverity:   strOpt(opts, "minSeverity", "info"),
		MinConfidence: strOpt(opts, "minConfidence", "low"),
	}); err != nil {
		return nil, err
	}

	var name string
	switch format {
	case "html":
		name = "findings.html"
	case "md":
		name = "findings.md"
	case "json":
		name = "findings.json"
	case "jsonl":
		name = "findings.jsonl"
	default:
		return nil, fmt.Errorf("unsupported format %q", format)
	}
	b, err := os.ReadFile(filepath.Join(runDir, name))
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"format":  format,
		"path":    filepath.Join(runDir, name),
		"content": string(b),
		"bytes":   len(b),
	}, nil
}

func cancel(this js.Value, args []js.Value) any {
	if activeCancel != nil {
		activeCancel()
		return map[string]any{"ok": true}
	}
	return map[string]any{"ok": false, "error": "no active scan"}
}
