//go:build js

// Package main provides the WASM-JS bridge API for Trajan browser execution.
//
// This file exports Go functions to JavaScript, enabling browser-based
// CI/CD security scanning and offensive security testing.
//
// All exported functions follow the pattern:
//   - Accept JSON-encoded parameters from JavaScript
//   - Return JSON-encoded results or errors
//   - Use context for cancellation support
//   - Include progress callbacks for long-running operations
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"syscall/js"
	"time"

	"github.com/praetorian-inc/trajan/internal/registry"
	adoplatform "github.com/praetorian-inc/trajan/pkg/azuredevops"
	"github.com/praetorian-inc/trajan/pkg/azuredevops/tokenprobe"
	"github.com/praetorian-inc/trajan/pkg/config"
	"github.com/praetorian-inc/trajan/pkg/detections"
	gitlabplatform "github.com/praetorian-inc/trajan/pkg/gitlab"
	"github.com/praetorian-inc/trajan/pkg/platforms"
	"github.com/praetorian-inc/trajan/pkg/scanner"
	"github.com/praetorian-inc/trajan/pkg/search"
	"github.com/praetorian-inc/trajan/pkg/storage"

	// Import all detections to trigger init() registration
	_ "github.com/praetorian-inc/trajan/pkg/detections/all"

	// GitLab detections - import for init() registration
	_ "github.com/praetorian-inc/trajan/pkg/gitlab/detections/ai"
	_ "github.com/praetorian-inc/trajan/pkg/gitlab/detections/includes"
	_ "github.com/praetorian-inc/trajan/pkg/gitlab/detections/injection"
	_ "github.com/praetorian-inc/trajan/pkg/gitlab/detections/mrcheckout"
	_ "github.com/praetorian-inc/trajan/pkg/gitlab/detections/mrsecrets"
	_ "github.com/praetorian-inc/trajan/pkg/gitlab/detections/permissions"
	_ "github.com/praetorian-inc/trajan/pkg/gitlab/detections/selfhostedrunner"
	_ "github.com/praetorian-inc/trajan/pkg/gitlab/detections/unpinned"

	// Azure DevOps detections - import for init() registration
	_ "github.com/praetorian-inc/trajan/pkg/azuredevops/detections/ai"
	// TODO: Uncomment when these packages are created
	// _ "github.com/praetorian-inc/trajan/pkg/azuredevops/detections/connections"
	// _ "github.com/praetorian-inc/trajan/pkg/azuredevops/detections/environmentgates"
	// _ "github.com/praetorian-inc/trajan/pkg/azuredevops/detections/forksecurity"
	// _ "github.com/praetorian-inc/trajan/pkg/azuredevops/detections/insecurepermissions"
	// _ "github.com/praetorian-inc/trajan/pkg/azuredevops/detections/insecuresecrets"
	// _ "github.com/praetorian-inc/trajan/pkg/azuredevops/detections/overpermconnections"
	// _ "github.com/praetorian-inc/trajan/pkg/azuredevops/detections/templates"
	// _ "github.com/praetorian-inc/trajan/pkg/azuredevops/detections/triggers"
	// _ "github.com/praetorian-inc/trajan/pkg/azuredevops/detections/unrestrictedpools"
)

const (
	// adoProxyBase is the local CORS proxy URL for Azure DevOps API requests
	adoProxyBase = "http://localhost:8080/azdo-proxy"
)

var (
	globalConfig  *config.Config
	globalStorage storage.Storage

	activeScanContext    context.Context
	activeScanCancelFunc context.CancelFunc
)

// validateBaseURL validates user-provided base URLs to prevent SSRF attacks.
// For security testing tools, we allow localhost and private networks (for testing internal infrastructure)
// but block cloud metadata services (169.254.169.254) to prevent credential theft.
func validateBaseURL(rawURL string) error {
	if rawURL == "" {
		return nil // Empty is allowed (uses default)
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL format: %w", err)
	}

	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return fmt.Errorf("unsupported URL scheme '%s' (only http/https allowed)", parsed.Scheme)
	}

	host := parsed.Hostname()
	if host == "" {
		return fmt.Errorf("URL must include hostname")
	}

	ip := net.ParseIP(host)

	// CRITICAL: Block AWS/GCP/Azure metadata services
	// These can leak cloud credentials even from localhost browser
	if ip != nil {
		if ip.String() == "169.254.169.254" {
			return fmt.Errorf("access to cloud metadata service (169.254.169.254) is forbidden")
		}
		if ip.String() == "169.254.169.253" {
			return fmt.Errorf("access to cloud metadata service (169.254.169.253) is forbidden")
		}
	}

	hostLower := strings.ToLower(host)
	metadataPatterns := []string{
		"169.254.169.254",
		"169.254.169.253",
		"metadata.google.internal",
		"metadata.azure.com",
	}
	for _, pattern := range metadataPatterns {
		if hostLower == pattern || strings.Contains(hostLower, pattern) {
			return fmt.Errorf("access to cloud metadata service is forbidden")
		}
	}

	ips, err := net.LookupIP(host)
	if err == nil && len(ips) > 0 {
		for _, resolvedIP := range ips {
			ipStr := resolvedIP.String()
			if ipStr == "169.254.169.254" || ipStr == "169.254.169.253" {
				return fmt.Errorf("hostname '%s' resolves to cloud metadata service %s", host, ipStr)
			}
		}
	}

	if matched, _ := regexp.MatchString(`^(0x[0-9a-fA-F]+|0[0-7]+|[0-9]{10,})$`, host); matched {
		if num, err := strconv.ParseUint(host, 0, 32); err == nil {
			ipBytes := []byte{
				byte(num >> 24),
				byte(num >> 16),
				byte(num >> 8),
				byte(num),
			}
			decodedIP := net.IP(ipBytes)
			ipStr := decodedIP.String()
			if ipStr == "169.254.169.254" || ipStr == "169.254.169.253" {
				return fmt.Errorf("numeric IP encoding resolves to cloud metadata service")
			}
		}
	}

	return nil
}

// validatePlatform validates the platform parameter to prevent injection
func validatePlatform(platform string) error {
	if platform == "" {
		return fmt.Errorf("platform is required")
	}
	validPlatforms := map[string]bool{
		"github":      true,
		"gitlab":      true,
		"azuredevops": true,
	}
	if !validPlatforms[platform] {
		return fmt.Errorf("unsupported platform: %s", platform)
	}
	return nil
}

// validateTarget validates target org/group/project names to prevent injection
func validateTarget(target string) error {
	if target == "" {
		return nil // Optional for some operations
	}
	if len(target) > 512 {
		return fmt.Errorf("target identifier too long (max 512 characters)")
	}
	if matched, _ := regexp.MatchString(`^[a-zA-Z0-9_.\/-]+$`, target); !matched {
		return fmt.Errorf("invalid characters in target identifier")
	}
	if strings.Contains(target, "..") {
		return fmt.Errorf("path traversal attempt detected")
	}
	return nil
}

// adoProxyTransport rewrites Azure DevOps API requests through the local proxy server
// to bypass browser CORS restrictions. In WASM, net/http uses the browser's fetch API
// which enforces CORS for cross-origin requests. Routing through localhost (same-origin)
// avoids this entirely. The local server.go proxy forwards the request server-side.
type adoProxyTransport struct {
	proxyBase string // e.g. "http://localhost:8080"
}

func (t *adoProxyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	host := req.URL.Host
	if host == "dev.azure.com" || strings.HasSuffix(host, ".dev.azure.com") {
		proxyURL, err := url.Parse(t.proxyBase)
		if err == nil {
			proxyURL.Path = "/azdo-proxy/" + host + req.URL.Path
			proxyURL.RawQuery = req.URL.RawQuery
			req = req.Clone(req.Context())
			req.URL = proxyURL
			req.Host = ""
		}
	}
	return http.DefaultTransport.RoundTrip(req)
}

func countWorkflows(sr *platforms.ScanResult) int {
	count := 0
	for _, wfs := range sr.Workflows {
		count += len(wfs)
	}
	return count
}

// Initialize sets up the WASM application (config, storage, plugin registration)
//
// JavaScript signature:
//
//	async function initialize(): Promise<{success: bool, error?: string}>
func Initialize(this js.Value, args []js.Value) interface{} {
	handler := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		resolve := args[0]
		reject := args[1]

		go func() {
			ctx := context.Background()

			localStorage := config.NewLocalStorage("trajan_config")
			cfg, err := localStorage.Load()
			if err != nil {
				cfg = config.DefaultConfig()
			}
			globalConfig = cfg

			stor := storage.NewIndexedDBStorage("trajan_storage", 1)
			if err := stor.Initialize(ctx); err != nil {
				reject.Invoke(map[string]interface{}{
					"success": false,
					"error":   fmt.Sprintf("failed to initialize storage: %v", err),
				})
				return
			}
			globalStorage = stor

			resolve.Invoke(map[string]interface{}{
				"success": true,
			})
		}()

		return nil
	})

	promiseConstructor := js.Global().Get("Promise")
	return promiseConstructor.New(handler)
}

// StartScan initiates a vulnerability scan
//
// JavaScript signature:
//
//	async function startScan(target: string, options: {
//	  platform?: string,
//	  token?: string,
//	  concurrent?: number,
//	  includeArchived?: boolean,
//	  onProgress?: (progress: number, message: string) => void
//	}): Promise<{scanId: string, error?: string}>
func StartScan(this js.Value, args []js.Value) interface{} {
	if len(args) < 2 {
		return js.ValueOf(map[string]interface{}{
			"error": "missing required arguments: target and options",
		})
	}

	target := args[0].String()
	options := args[1]

	handler := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		resolve := args[0]
		reject := args[1]

		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
			activeScanContext = ctx
			activeScanCancelFunc = cancel

			platform := "github"
			if !options.Get("platform").IsUndefined() {
				platform = options.Get("platform").String()
			}

			token := globalConfig.GitHub.Token
			if !options.Get("token").IsUndefined() {
				optToken := options.Get("token").String()
				if optToken != "" {
					token = optToken
				}
			}

			_ = globalConfig.Scan.Concurrent // Will use when implementing full scan
			if !options.Get("concurrent").IsUndefined() {
				_ = options.Get("concurrent").Int()
			}

			_ = globalConfig.Scan.IncludeArchived // Will use when implementing full scan
			if !options.Get("includeArchived").IsUndefined() {
				_ = options.Get("includeArchived").Bool()
			}

			scope := "repo"
			if !options.Get("scope").IsUndefined() {
				scope = options.Get("scope").String()
			}

			var progressCallback js.Value
			if !options.Get("onProgress").IsUndefined() {
				progressCallback = options.Get("onProgress")
			}

			scanID := fmt.Sprintf("scan_%d", time.Now().UnixNano())

			reportProgress := func(percent int, message string) {
				if !progressCallback.IsUndefined() && !progressCallback.IsNull() {
					progressCallback.Invoke(percent, message)
				}
			}

			reportProgress(0, "Initializing scan...")

			var findings []detections.Finding
			var scanErr error

			switch platform {
			case "github":
				reject.Invoke(map[string]interface{}{
					"error": "github scanning is not supported in the browser; use the trajan CLI",
				})
				return

			case "gitlab", "azuredevops", "bitbucket":
				reportProgress(5, fmt.Sprintf("Connecting to %s API...", platform))

				baseURL := ""
				if !options.Get("baseURL").IsUndefined() {
					baseURL = options.Get("baseURL").String()

					if baseURL != "" {
						if err := validateBaseURL(baseURL); err != nil {
							reject.Invoke(map[string]interface{}{
								"error": fmt.Sprintf("invalid base URL: %v", err),
							})
							return
						}
					}
				}

				capabilities := ""
				if !options.Get("capabilities").IsUndefined() {
					capabilities = options.Get("capabilities").String()
				}

				plat, err := registry.GetPlatform(platform)
				if err != nil {
					reject.Invoke(map[string]interface{}{"error": fmt.Sprintf("platform not found: %v", err)})
					return
				}

				config := platforms.Config{
					Token:       token,
					BaseURL:     baseURL,
					Concurrency: 10,
				}

				switch platform {
				case "gitlab":
					config.GitLab = &platforms.GitLabAuth{Token: token}
				case "azuredevops":
					config.AzureDevOps = &platforms.AzureDevOpsAuth{PAT: token, Organization: baseURL}
					// Proxy ADO API calls through localhost to bypass browser CORS restrictions
					if origin := js.Global().Get("location").Get("origin").String(); origin != "" {
						config.HTTPTransport = &adoProxyTransport{proxyBase: origin}
					}
				}

				if err := plat.Init(ctx, config); err != nil {
					reject.Invoke(map[string]interface{}{"error": fmt.Sprintf("init failed: %v", err)})
					return
				}

				var targetType platforms.TargetType
				switch scope {
				case "repo":
					targetType = platforms.TargetRepo
				case "org":
					targetType = platforms.TargetOrg
				case "user":
					targetType = platforms.TargetUser
				default:
					targetType = platforms.TargetRepo
				}

				targetObj := platforms.Target{Type: targetType, Value: target}

				reportProgress(30, "Fetching workflows...")
				result, err := plat.Scan(ctx, targetObj)
				if err != nil {
					reject.Invoke(map[string]interface{}{"error": fmt.Sprintf("scan failed: %v", err)})
					return
				}

				repoCount := len(result.Repositories)
				workflowCount := 0
				reposWithPipelines := 0
				for _, wfs := range result.Workflows {
					workflowCount += len(wfs)
					if len(wfs) > 0 {
						reposWithPipelines++
					}
				}

				for _, scanRepoErr := range result.Errors {
					fmt.Fprintf(os.Stderr, "[trajan] scan warning: %v\n", scanRepoErr)
				}

				progressMsg := fmt.Sprintf("Found %d repos, %d with pipelines (%d total workflows), running detectors...", repoCount, reposWithPipelines, workflowCount)
				if len(result.Errors) > 0 {
					progressMsg += fmt.Sprintf(" (%d repos skipped, see console)", len(result.Errors))
				}
				reportProgress(60, progressMsg)

				allPlugins := registry.GetDetections(platform)
				executor := scanner.NewDetectionExecutor(allPlugins, 10)
				executor.SetMetadata("platform", platform)
				execResult, err := executor.Execute(ctx, result.Workflows)
				if err != nil {
					reject.Invoke(map[string]interface{}{"error": fmt.Sprintf("detectors failed: %v", err)})
					return
				}

				findings = execResult.Findings

				if capabilities != "" {
					filtered := make([]detections.Finding, 0)
					capList := strings.Split(capabilities, ",")
					allowedCaps := make(map[detections.VulnerabilityType]bool)
					for _, cap := range capList {
						allowedCaps[detections.VulnerabilityType(strings.TrimSpace(cap))] = true
					}
					for _, f := range findings {
						if allowedCaps[f.Type] {
							filtered = append(filtered, f)
						}
					}
					findings = filtered
				}

				workflowContentCache := make(map[string]string)
				for repoSlug, workflows := range result.Workflows {
					for _, wf := range workflows {
						key := fmt.Sprintf("%s/%s", repoSlug, wf.Path)
						workflowContentCache[key] = string(wf.Content)
					}
				}

				for i := range findings {
					key := fmt.Sprintf("%s/%s", findings[i].Repository, findings[i].Workflow)
					if content, ok := workflowContentCache[key]; ok {
						findings[i].WorkflowContent = content
					}
				}

				scanErr = nil
				completionMsg := fmt.Sprintf("Scan complete - %d vulnerabilities across %d repos", len(findings), repoCount)
				if len(result.Errors) > 0 {
					completionMsg += fmt.Sprintf("; %d repos skipped (open console for details)", len(result.Errors))
				}
				reportProgress(100, completionMsg)

			default:
				reject.Invoke(map[string]interface{}{
					"error": fmt.Sprintf("unsupported platform: %s", platform),
				})
				return
			}

			if scanErr != nil {
				reject.Invoke(map[string]interface{}{
					"error": fmt.Sprintf("scan failed: %v", scanErr),
				})
				return
			}

			cache := &storage.ScanCache{
				Key:       scanID,
				URL:       target,
				Results:   findings,
				CachedAt:  time.Now(),
				TTL:       globalConfig.Scan.CacheTTL,
				ExpiresAt: time.Now().Add(time.Duration(globalConfig.Scan.CacheTTL) * time.Second),
			}

			if err := globalStorage.SaveScanCache(ctx, cache); err != nil {
				fmt.Printf("failed to cache scan results: %v\n", err)
			}

			resolve.Invoke(map[string]interface{}{
				"scanId": scanID,
			})
		}()

		return nil
	})

	promiseConstructor := js.Global().Get("Promise")
	return promiseConstructor.New(handler)
}

// GetResults retrieves scan results by scan ID
//
// JavaScript signature:
//
//	async function getResults(scanId: string): Promise<{findings: Array, error?: string}>
func GetResults(this js.Value, args []js.Value) interface{} {
	if len(args) < 1 {
		return js.ValueOf(map[string]interface{}{
			"error": "missing required argument: scanId",
		})
	}

	scanID := args[0].String()

	handler := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		resolve := args[0]
		reject := args[1]

		go func() {
			ctx := context.Background()

			cache, err := globalStorage.LoadScanCache(ctx, scanID)
			if err != nil {
				reject.Invoke(map[string]interface{}{
					"error": fmt.Sprintf("failed to load scan results: %v", err),
				})
				return
			}

			findingsJSON, err := json.Marshal(cache.Results)
			if err != nil {
				reject.Invoke(map[string]interface{}{
					"error": fmt.Sprintf("failed to serialize findings: %v", err),
				})
				return
			}

			resolve.Invoke(map[string]interface{}{
				"findings": string(findingsJSON),
			})
		}()

		return nil
	})

	promiseConstructor := js.Global().Get("Promise")
	return promiseConstructor.New(handler)
}

// ExportResults exports scan results in specified format
//
// JavaScript signature:
//
//	async function exportResults(scanId: string, format: 'json' | 'sarif'): Promise<{data: string, error?: string}>
func ExportResults(this js.Value, args []js.Value) interface{} {
	if len(args) < 2 {
		return js.ValueOf(map[string]interface{}{
			"error": "missing required arguments: scanId and format",
		})
	}

	scanID := args[0].String()
	format := args[1].String()

	handler := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		resolve := args[0]
		reject := args[1]

		go func() {
			ctx := context.Background()

			cache, err := globalStorage.LoadScanCache(ctx, scanID)
			if err != nil {
				reject.Invoke(map[string]interface{}{
					"error": fmt.Sprintf("failed to load scan results: %v", err),
				})
				return
			}

			var exportData string
			switch format {
			case "json":
				data, err := json.MarshalIndent(cache.Results, "", "  ")
				if err != nil {
					reject.Invoke(map[string]interface{}{
						"error": fmt.Sprintf("failed to export as JSON: %v", err),
					})
					return
				}
				exportData = string(data)

			case "sarif":
				// TODO: Implement SARIF export when results package is complete
				reject.Invoke(map[string]interface{}{
					"error": "SARIF export not yet implemented",
				})
				return

			default:
				reject.Invoke(map[string]interface{}{
					"error": fmt.Sprintf("unsupported export format: %s", format),
				})
				return
			}

			resolve.Invoke(map[string]interface{}{
				"data": exportData,
			})
		}()

		return nil
	})

	promiseConstructor := js.Global().Get("Promise")
	return promiseConstructor.New(handler)
}

// ExecuteAttack executes an attack plugin
//
// JavaScript signature:
//
//	async function executeAttack(plugin: string, target: string, options: {
//	  token: string,
//	  authorized: bool,
//	  saveSession?: bool,
//	  dryRun?: bool,
//	  branch?: string,
//	  cleanup?: bool,
//	  payload?: string,
//	  metadata?: object,
//	  onProgress?: (message: string) => void
//	}): Promise<{result: object, error?: string}>
func ExecuteAttack(this js.Value, args []js.Value) interface{} {
	if len(args) < 3 {
		return js.ValueOf(map[string]interface{}{
			"error": "missing required arguments: plugin, target, and options",
		})
	}

	_ = args[0].String()
	_ = args[1].String()

	handler := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		reject := args[1]

		go func() {
			reject.Invoke(map[string]interface{}{
				"error": "attack execution is not supported in the browser; use the trajan CLI",
			})
		}()

		return nil
	})

	promiseConstructor := js.Global().Get("Promise")
	return promiseConstructor.New(handler)
}

// CleanupSession cleans up attack artifacts for a session
//
// JavaScript signature:
//
//	async function cleanupSession(sessionId: string, token: string): Promise<{summary: object, error?: string}>
func CleanupSession(this js.Value, args []js.Value) interface{} {
	if len(args) < 2 {
		return js.ValueOf(map[string]interface{}{
			"error": "missing required arguments: sessionId and token",
		})
	}

	_ = args[0].String()
	_ = args[1].String()

	handler := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		reject := args[1]

		go func() {
			reject.Invoke(map[string]interface{}{
				"error": "attack session cleanup is not supported in the browser; use the trajan CLI",
			})
		}()

		return nil
	})

	promiseConstructor := js.Global().Get("Promise")
	return promiseConstructor.New(handler)
}

// GetSessionStatus queries attack session state
//
// JavaScript signature:
//
//	async function getSessionStatus(sessionId: string): Promise<{session: object, error?: string}>
func GetSessionStatus(this js.Value, args []js.Value) interface{} {
	if len(args) < 1 {
		return js.ValueOf(map[string]interface{}{
			"error": "missing required argument: sessionId",
		})
	}

	sessionID := args[0].String()

	handler := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		resolve := args[0]
		reject := args[1]

		go func() {
			ctx := context.Background()

			session, err := globalStorage.LoadSession(ctx, sessionID)
			if err != nil {
				reject.Invoke(map[string]interface{}{
					"error": fmt.Sprintf("failed to load session: %v", err),
				})
				return
			}

			sessionJSON, err := json.Marshal(session)
			if err != nil {
				reject.Invoke(map[string]interface{}{
					"error": fmt.Sprintf("failed to serialize session: %v", err),
				})
				return
			}

			resolve.Invoke(map[string]interface{}{
				"session": string(sessionJSON),
			})
		}()

		return nil
	})

	promiseConstructor := js.Global().Get("Promise")
	return promiseConstructor.New(handler)
}

// ListAttackPlugins enumerates available attack plugins
//
// JavaScript signature:
//
//	async function listAttackPlugins(): Promise<{plugins: Array, error?: string}>
func ListAttackPlugins(this js.Value, args []js.Value) interface{} {
	handler := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		resolve := args[0]
		reject := args[1]

		go func() {
			pluginNames := registry.ListAttackPlugins()

			var plugins []map[string]interface{}
			for _, name := range pluginNames {
				plugin, err := registry.GetAttackPluginByName(name)
				if err != nil {
					continue
				}
				plugins = append(plugins, map[string]interface{}{
					"id":          name,          // Namespaced key (e.g. "github/secrets-dump") for lookup
					"name":        plugin.Name(), // Display name
					"description": plugin.Description(),
					"category":    string(plugin.Category()),
				})
			}

			pluginsJSON, err := json.Marshal(plugins)
			if err != nil {
				reject.Invoke(map[string]interface{}{
					"error": fmt.Sprintf("failed to serialize plugin list: %v", err),
				})
				return
			}

			resolve.Invoke(map[string]interface{}{
				"plugins": string(pluginsJSON),
			})
		}()

		return nil
	})

	promiseConstructor := js.Global().Get("Promise")
	return promiseConstructor.New(handler)
}

// ListSessions retrieves all attack sessions
//
// JavaScript signature:
//
//	async function listSessions(): Promise<{sessions: Array, error?: string}>
func ListSessions(this js.Value, args []js.Value) interface{} {
	handler := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		resolve := args[0]
		reject := args[1]

		go func() {
			ctx := context.Background()

			sessions, err := globalStorage.ListSessions(ctx)
			if err != nil {
				reject.Invoke(map[string]interface{}{
					"error": fmt.Sprintf("failed to list sessions: %v", err),
				})
				return
			}

			sessionsJSON, err := json.Marshal(sessions)
			if err != nil {
				reject.Invoke(map[string]interface{}{
					"error": fmt.Sprintf("failed to serialize sessions: %v", err),
				})
				return
			}

			resolve.Invoke(map[string]interface{}{
				"sessions": string(sessionsJSON),
			})
		}()

		return nil
	})

	promiseConstructor := js.Global().Get("Promise")
	return promiseConstructor.New(handler)
}

// ConfigSet updates a configuration value
//
// JavaScript signature:
//
//	async function configSet(key: string, value: any): Promise<{success: bool, error?: string}>
func ConfigSet(this js.Value, args []js.Value) interface{} {
	if len(args) < 2 {
		return js.ValueOf(map[string]interface{}{
			"error": "missing required arguments: key and value",
		})
	}

	key := args[0].String()
	value := args[1]

	handler := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		resolve := args[0]
		reject := args[1]

		go func() {
			var goValue interface{}
			switch value.Type() {
			case js.TypeString:
				goValue = value.String()
			case js.TypeBoolean:
				goValue = value.Bool()
			case js.TypeNumber:
				goValue = value.Float()
			default:
				reject.Invoke(map[string]interface{}{
					"error": "unsupported value type",
				})
				return
			}

			if err := globalConfig.Set(key, goValue); err != nil {
				reject.Invoke(map[string]interface{}{
					"error": fmt.Sprintf("failed to set config: %v", err),
				})
				return
			}

			localStorage := config.NewLocalStorage("trajan_config")
			if err := localStorage.Save(globalConfig); err != nil {
				reject.Invoke(map[string]interface{}{
					"error": fmt.Sprintf("failed to persist config: %v", err),
				})
				return
			}

			resolve.Invoke(map[string]interface{}{
				"success": true,
			})
		}()

		return nil
	})

	promiseConstructor := js.Global().Get("Promise")
	return promiseConstructor.New(handler)
}

// ConfigGet reads a configuration value
//
// JavaScript signature:
//
//	async function configGet(key: string): Promise<{value: any, error?: string}>
func ConfigGet(this js.Value, args []js.Value) interface{} {
	if len(args) < 1 {
		return js.ValueOf(map[string]interface{}{
			"error": "missing required argument: key",
		})
	}

	key := args[0].String()

	handler := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		resolve := args[0]
		reject := args[1]

		go func() {
			value, err := globalConfig.Get(key)
			if err != nil {
				reject.Invoke(map[string]interface{}{
					"error": fmt.Sprintf("failed to get config: %v", err),
				})
				return
			}

			resolve.Invoke(map[string]interface{}{
				"value": value,
			})
		}()

		return nil
	})

	promiseConstructor := js.Global().Get("Promise")
	return promiseConstructor.New(handler)
}

// CancelScan cancels an active scan
//
// JavaScript signature:
//
//	function cancelScan(): {success: bool}
func CancelScan(this js.Value, args []js.Value) interface{} {
	if activeScanCancelFunc != nil {
		activeScanCancelFunc()
		activeScanCancelFunc = nil
		activeScanContext = nil
		return js.ValueOf(map[string]interface{}{
			"success": true,
		})
	}
	return js.ValueOf(map[string]interface{}{
		"success": false,
		"error":   "no active scan to cancel",
	})
}

// ValidateToken validates a GitHub token and returns user info and organizations
//
// JavaScript signature:
//
//	async function trajanValidateToken(options: {
//	  token: string
//	}): Promise<{result: string, error?: string}>
func ValidateToken(this js.Value, args []js.Value) interface{} {
	if len(args) < 1 {
		return js.ValueOf(map[string]interface{}{
			"error": "missing required argument: options",
		})
	}

	options := args[0]

	handler := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		resolve := args[0]
		reject := args[1]

		go func() {
			ctx := context.Background()

			platform := "github"
			if !options.Get("platform").IsUndefined() {
				platform = options.Get("platform").String()
			}

			switch platform {
			case "gitlab":
				validateGitLabToken(ctx, options, resolve, reject)
			case "azuredevops":
				validateAzureDevOpsToken(ctx, options, resolve, reject)
			default:
				reject.Invoke(map[string]interface{}{
					"error": "github token validation is not supported in the browser; use the trajan CLI",
				})
			}
		}()

		return nil
	})

	promiseConstructor := js.Global().Get("Promise")
	return promiseConstructor.New(handler)
}

func validateGitLabToken(ctx context.Context, options js.Value, resolve, reject js.Value) {
	token := ""
	if !options.Get("token").IsUndefined() {
		token = options.Get("token").String()
	}

	baseURL := ""
	if !options.Get("url").IsUndefined() {
		urlStr := options.Get("url").String()
		if urlStr != "" {
			baseURL = urlStr
		}
	}

	glPlatform := gitlabplatform.NewPlatform()

	config := platforms.Config{
		Token:   token,
		BaseURL: baseURL,
		GitLab:  &platforms.GitLabAuth{Token: token},
	}

	if err := glPlatform.Init(ctx, config); err != nil {
		reject.Invoke(map[string]interface{}{"error": fmt.Sprintf("init failed: %v", err)})
		return
	}

	result, err := glPlatform.EnumerateToken(ctx)
	if err != nil {
		reject.Invoke(map[string]interface{}{"error": fmt.Sprintf("token validation failed: %v", err)})
		return
	}

	if result.User == nil {
		errMsg := "no user info returned"
		if len(result.Errors) > 0 {
			errMsg = result.Errors[0]
		}
		reject.Invoke(map[string]interface{}{"error": errMsg})
		return
	}

	// Match the shape expected by displayValidationResults in the browser
	out := map[string]interface{}{
		"user": map[string]interface{}{
			"login": result.User.Username,
			"name":  result.User.Name,
		},
		"token_type": result.TokenType,
		"is_admin":   result.IsAdmin,
	}

	if result.Token != nil {
		out["scopes"] = result.Token.Scopes
		if result.Token.ExpiresAt != nil {
			out["expiration"] = *result.Token.ExpiresAt
		}
	}

	if len(result.Groups) > 0 {
		groups := make([]map[string]interface{}, len(result.Groups))
		for i, g := range result.Groups {
			groups[i] = map[string]interface{}{
				"name":      g.Name,
				"full_path": g.FullPath,
			}
		}
		out["groups"] = groups
	}

	if result.RateLimit != nil {
		out["rate_limit"] = map[string]interface{}{
			"remaining": result.RateLimit.Remaining,
			"limit":     result.RateLimit.Limit,
		}
	}

	resultJSON, err := json.Marshal(out)
	if err != nil {
		reject.Invoke(map[string]interface{}{"error": fmt.Sprintf("marshal failed: %v", err)})
		return
	}

	resolve.Invoke(map[string]interface{}{"result": string(resultJSON)})
}

func validateAzureDevOpsToken(ctx context.Context, options js.Value, resolve, reject js.Value) {
	token := ""
	if !options.Get("token").IsUndefined() {
		token = options.Get("token").String()
	}

	orgURL := ""
	if !options.Get("url").IsUndefined() {
		orgURL = options.Get("url").String()
	}

	if orgURL == "" {
		reject.Invoke(map[string]interface{}{"error": "Organization URL is required for Azure DevOps (e.g., https://dev.azure.com/myorg)"})
		return
	}

	if token == "" {
		reject.Invoke(map[string]interface{}{"error": "PAT is required for Azure DevOps"})
		return
	}

	// Proxy ADO API calls through localhost to bypass browser CORS restrictions
	var clientOpts []adoplatform.ClientOption
	if origin := js.Global().Get("location").Get("origin").String(); origin != "" {
		clientOpts = append(clientOpts, adoplatform.WithHTTPTransport(&adoProxyTransport{proxyBase: origin}))
	}
	client := adoplatform.NewClient(orgURL, token, clientOpts...)
	prober := tokenprobe.NewProber(client)
	prober.SetFeedsClient(client.FeedsClient())

	result, err := prober.Probe(ctx)
	if err != nil {
		reject.Invoke(map[string]interface{}{"error": fmt.Sprintf("token probe failed: %v", err)})
		return
	}

	if !result.Valid {
		reject.Invoke(map[string]interface{}{"error": "invalid PAT or no access to organization"})
		return
	}

	serviceOwner := ""
	if connData, cdErr := client.GetConnectionData(ctx); cdErr == nil {
		serviceOwner = connData.LocationServiceData.ServiceOwner
	}

	caps := make([]string, len(result.Capabilities))
	for i, cap := range result.Capabilities {
		caps[i] = string(cap)
	}

	projects := make([]map[string]interface{}, len(result.Projects))
	for i, proj := range result.Projects {
		projects[i] = map[string]interface{}{
			"name":       proj.Name,
			"visibility": proj.Visibility,
		}
	}

	type adoPermResult struct {
		Name    string `json:"name"`
		Allowed bool   `json:"allowed"`
	}
	type adoProjectPerms struct {
		Project string          `json:"project"`
		Build   []adoPermResult `json:"build"`
		Git     []adoPermResult `json:"git"`
	}
	const (
		adoBuildNS = "33344d9c-fc72-4d6f-aba5-fa317101a7e9"
		adoGitNS   = "2e9eb7ed-3c0a-47d4-87c1-0ffdd275fd87"
	)
	buildChecks := []struct {
		bit  int
		name string
	}{
		{1, "View builds"},
		{128, "Queue builds"},
		{1024, "View build definition"},
		{2048, "Edit build definition"},
		{8, "Delete builds"},
		{512, "Stop builds"},
		{16384, "Administer build permissions"},
	}
	gitChecks := []struct {
		bit  int
		name string
	}{
		{1, "Administer"},
		{2, "Read"},
		{4, "Contribute"},
		{8, "Force push"},
		{16, "Create branch"},
		{128, "Bypass policies when pushing"},
		{16384, "Contribute to pull requests"},
		{32768, "Bypass policies when completing PR"},
	}
	permissions := make([]adoProjectPerms, 0, len(result.Projects))
	for _, proj := range result.Projects {
		pp := adoProjectPerms{Project: proj.Name}
		for _, check := range buildChecks {
			allowed, checkErr := client.CheckPermission(ctx, adoBuildNS, check.bit, proj.ID)
			if checkErr != nil {
				continue
			}
			pp.Build = append(pp.Build, adoPermResult{Name: check.name, Allowed: allowed})
		}
		for _, check := range gitChecks {
			allowed, checkErr := client.CheckPermission(ctx, adoGitNS, check.bit, "repoV2/"+proj.ID)
			if checkErr != nil {
				continue
			}
			pp.Git = append(pp.Git, adoPermResult{Name: check.name, Allowed: allowed})
		}
		permissions = append(permissions, pp)
	}

	userName := ""
	if result.User != nil {
		userName = result.User.DisplayName
	}

	out := map[string]interface{}{
		"user": map[string]interface{}{
			"login": userName,
			"name":  userName,
		},
		"token_type":               "PAT",
		"scopes":                   caps,
		"groups":                   projects,
		"service_owner":            serviceOwner,
		"project_count":            result.ProjectCount,
		"repository_count":         result.RepositoryCount,
		"pipeline_count":           result.PipelineCount,
		"agent_pool_count":         result.AgentPoolCount,
		"variable_group_count":     result.VariableGroupCount,
		"service_connection_count": result.ServiceConnectionCount,
		"artifact_feed_count":      result.ArtifactFeedCount,
		"has_secret_variables":     result.HasSecretVariables,
		"has_self_hosted_agents":   result.HasSelfHostedAgents,
		"permissions":              permissions,
	}

	resultJSON, err := json.Marshal(out)
	if err != nil {
		reject.Invoke(map[string]interface{}{"error": fmt.Sprintf("marshal failed: %v", err)})
		return
	}

	resolve.Invoke(map[string]interface{}{"result": string(resultJSON)})
}

func ScanSecrets(this js.Value, args []js.Value) interface{} {
	return githubUnsupported("secret scanning")
}

func ScanRunners(this js.Value, args []js.Value) interface{} {
	return githubUnsupported("runner scanning")
}

func SelfEnumerate(this js.Value, args []js.Value) interface{} {
	return githubUnsupported("self enumeration")
}

// githubUnsupported returns a rejected promise indicating the operation is
// GitHub-only and not available in the browser; use the trajan CLI instead.
func githubUnsupported(operation string) interface{} {
	handler := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		reject := args[1]
		go func() {
			reject.Invoke(map[string]interface{}{
				"error": fmt.Sprintf("github %s is not supported in the browser; use the trajan CLI", operation),
			})
		}()
		return nil
	})

	promiseConstructor := js.Global().Get("Promise")
	return promiseConstructor.New(handler)
}


type ProgressCallback func(percent int, message string)

func getProgressCallback(options js.Value) ProgressCallback {
	var progressCallback js.Value
	if !options.Get("onProgress").IsUndefined() {
		progressCallback = options.Get("onProgress")
	}

	return func(percent int, message string) {
		if !progressCallback.IsUndefined() && !progressCallback.IsNull() {
			progressCallback.Invoke(percent, message)
		}
	}
}

// Enumerate performs platform-specific resource enumeration
//
// JavaScript signature:
//
//	async function trajanEnumerate(
//	  platform: string,
//	  operation: string,
//	  options: {
//	    token: string,
//	    target?: string,
//	    baseURL?: string,
//	    onProgress?: (percent: number, message: string) => void
//	  }
//	): Promise<{result: string, error?: string}>
func Enumerate(this js.Value, args []js.Value) interface{} {
	if len(args) < 3 {
		return js.ValueOf(map[string]interface{}{
			"error": "missing required arguments: platform, operation, and options",
		})
	}

	platform := args[0].String()
	operation := args[1].String()
	options := args[2]

	if err := validatePlatform(platform); err != nil {
		return js.ValueOf(map[string]interface{}{
			"error": err.Error(),
		})
	}

	if !options.Get("target").IsUndefined() {
		target := options.Get("target").String()
		if err := validateTarget(target); err != nil {
			return js.ValueOf(map[string]interface{}{
				"error": err.Error(),
			})
		}
	}

	handler := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		resolve := args[0]
		reject := args[1]

		go func() {
			ctx := context.Background()

			switch platform {
			case "github":
				reject.Invoke(map[string]interface{}{
					"error": "github enumeration is not supported in the browser; use the trajan CLI",
				})
			case "gitlab":
				handleGitLabEnumerate(ctx, operation, options, resolve, reject)
			case "azuredevops":
				handleAzureDevOpsEnumerate(ctx, operation, options, resolve, reject)
			default:
				reject.Invoke(map[string]interface{}{
					"error": fmt.Sprintf("unsupported platform: %s", platform),
				})
			}
		}()

		return nil
	})

	promiseConstructor := js.Global().Get("Promise")
	return promiseConstructor.New(handler)
}

func handleGitLabEnumerate(ctx context.Context, operation string, options js.Value, resolve, reject js.Value) {
	token := options.Get("token").String()
	if token == "" {
		reject.Invoke(map[string]interface{}{"error": "token required"})
		return
	}

	baseURL := "https://gitlab.com"
	if !options.Get("baseURL").IsUndefined() && options.Get("baseURL").String() != "" {
		baseURL = options.Get("baseURL").String()
		if err := validateBaseURL(baseURL); err != nil {
			reject.Invoke(map[string]interface{}{
				"error": fmt.Sprintf("invalid base URL: %v", err),
			})
			return
		}
	}

	target := ""
	if !options.Get("target").IsUndefined() {
		target = options.Get("target").String()
	}

	progressCallback := getProgressCallback(options)

	progressCallback(10, "Initializing GitLab platform...")
	platform := gitlabplatform.NewPlatform()

	config := platforms.Config{
		Token:   token,
		BaseURL: baseURL,
	}

	if err := platform.Init(ctx, config); err != nil {
		reject.Invoke(map[string]interface{}{"error": fmt.Sprintf("failed to initialize platform: %v", err)})
		return
	}

	switch operation {
	case "projects":
		enumerateGitLabProjects(ctx, platform, target, progressCallback, resolve, reject)
	case "groups":
		enumerateGitLabGroups(ctx, platform, progressCallback, resolve, reject)
	case "secrets":
		enumerateGitLabSecrets(ctx, platform, target, progressCallback, resolve, reject)
	case "branch-protections", "protections":
		enumerateGitLabBranchProtections(ctx, platform, target, progressCallback, resolve, reject)
	case "runners":
		enumerateGitLabRunners(ctx, platform, target, progressCallback, resolve, reject)
	default:
		reject.Invoke(map[string]interface{}{
			"error": fmt.Sprintf("unsupported GitLab operation: %s", operation),
		})
	}
}

func enumerateGitLabProjects(ctx context.Context, platform *gitlabplatform.Platform, target string, progressCallback ProgressCallback, resolve, reject js.Value) {
	progressCallback(20, "Enumerating projects...")

	var targetType platforms.TargetType
	if target != "" {
		targetType = platforms.TargetOrg // Group in GitLab
	} else {
		targetType = platforms.TargetUser
	}

	result, err := platform.EnumerateProjects(ctx, platforms.Target{Type: targetType, Value: target})
	if err != nil {
		reject.Invoke(map[string]interface{}{"error": err.Error()})
		return
	}

	progressCallback(100, "Complete")

	jsonBytes, err := json.Marshal(result)
	if err != nil {
		reject.Invoke(map[string]interface{}{"error": fmt.Sprintf("failed to marshal results: %v", err)})
		return
	}

	resolve.Invoke(map[string]interface{}{
		"result": string(jsonBytes),
	})
}

func enumerateGitLabGroups(ctx context.Context, platform *gitlabplatform.Platform, progressCallback ProgressCallback, resolve, reject js.Value) {
	progressCallback(20, "Enumerating groups...")

	result, err := platform.EnumerateGroups(ctx, false) // recursive=false (matches CLI default)
	if err != nil {
		reject.Invoke(map[string]interface{}{"error": err.Error()})
		return
	}

	progressCallback(100, "Complete")

	jsonBytes, err := json.Marshal(result)
	if err != nil {
		reject.Invoke(map[string]interface{}{"error": fmt.Sprintf("failed to marshal results: %v", err)})
		return
	}

	resolve.Invoke(map[string]interface{}{
		"result": string(jsonBytes),
	})
}

func enumerateGitLabSecrets(ctx context.Context, platform *gitlabplatform.Platform, target string, progressCallback ProgressCallback, resolve, reject js.Value) {
	if target == "" {
		reject.Invoke(map[string]interface{}{"error": "target project required for secrets enumeration"})
		return
	}

	progressCallback(20, "Enumerating secrets...")

	result, err := platform.EnumerateSecrets(ctx, platforms.Target{Type: platforms.TargetRepo, Value: target})
	if err != nil {
		reject.Invoke(map[string]interface{}{"error": err.Error()})
		return
	}

	progressCallback(100, "Complete")

	jsonBytes, err := json.Marshal(result)
	if err != nil {
		reject.Invoke(map[string]interface{}{"error": fmt.Sprintf("failed to marshal results: %v", err)})
		return
	}

	resolve.Invoke(map[string]interface{}{
		"result": string(jsonBytes),
	})
}

func enumerateGitLabBranchProtections(ctx context.Context, platform *gitlabplatform.Platform, target string, progressCallback ProgressCallback, resolve, reject js.Value) {
	if target == "" {
		reject.Invoke(map[string]interface{}{"error": "target project required for branch protections"})
		return
	}

	progressCallback(20, "Enumerating branch protections...")

	result, err := platform.EnumerateBranchProtections(ctx, platforms.Target{Type: platforms.TargetRepo, Value: target})
	if err != nil {
		reject.Invoke(map[string]interface{}{"error": err.Error()})
		return
	}

	progressCallback(100, "Complete")

	jsonBytes, err := json.Marshal(result)
	if err != nil {
		reject.Invoke(map[string]interface{}{"error": fmt.Sprintf("failed to marshal results: %v", err)})
		return
	}

	resolve.Invoke(map[string]interface{}{
		"result": string(jsonBytes),
	})
}

func enumerateGitLabRunners(ctx context.Context, platform *gitlabplatform.Platform, target string, progressCallback ProgressCallback, resolve, reject js.Value) {
	if target == "" {
		reject.Invoke(map[string]interface{}{"error": "target project required for runners enumeration"})
		return
	}

	progressCallback(20, "Enumerating runners...")

	result, err := platform.EnumerateRunners(ctx, target, false, false) // includeGroup=false, includeInstance=false (matches CLI default)
	if err != nil {
		reject.Invoke(map[string]interface{}{"error": err.Error()})
		return
	}

	client := platform.Client()
	if len(result.ProjectRunners) > 0 {
		enriched, _ := client.EnrichRunnersWithDetails(ctx, result.ProjectRunners)
		result.ProjectRunners = enriched
	}
	if len(result.GroupRunners) > 0 {
		enriched, _ := client.EnrichRunnersWithDetails(ctx, result.GroupRunners)
		result.GroupRunners = enriched
	}
	if len(result.InstanceRunners) > 0 {
		enriched, _ := client.EnrichRunnersWithDetails(ctx, result.InstanceRunners)
		result.InstanceRunners = enriched
	}

	progressCallback(100, "Complete")

	jsonBytes, err := json.Marshal(result)
	if err != nil {
		reject.Invoke(map[string]interface{}{"error": fmt.Sprintf("failed to marshal results: %v", err)})
		return
	}

	resolve.Invoke(map[string]interface{}{
		"result": string(jsonBytes),
	})
}

func handleAzureDevOpsEnumerate(ctx context.Context, operation string, options js.Value, resolve, reject js.Value) {
	token := options.Get("token").String()
	if token == "" {
		reject.Invoke(map[string]interface{}{"error": "token required"})
		return
	}

	org := ""
	if !options.Get("target").IsUndefined() {
		org = options.Get("target").String()
	}

	if org == "" {
		reject.Invoke(map[string]interface{}{"error": "organization required for Azure DevOps operations"})
		return
	}

	project := ""
	if !options.Get("project").IsUndefined() {
		project = options.Get("project").String()
	}

	target := project

	progressCallback := getProgressCallback(options)
	progressCallback(10, "Initializing Azure DevOps client...")

	switch operation {
	case "projects":
		enumerateADOProjects(ctx, org, token, progressCallback, resolve, reject)
	case "repos", "repositories":
		enumerateADORepos(ctx, org, token, target, progressCallback, resolve, reject)
	case "pipelines":
		enumerateADOPipelines(ctx, org, token, target, progressCallback, resolve, reject)
	case "variable-groups", "variables":
		enumerateADOVariables(ctx, org, token, target, progressCallback, resolve, reject)
	case "service-connections", "connections":
		enumerateADOConnections(ctx, org, token, target, progressCallback, resolve, reject)
	case "agent-pools", "agents":
		enumerateADOAgentPools(ctx, org, token, progressCallback, resolve, reject)
	case "attack-paths":
		enumerateADOAttackPaths(ctx, org, token, target, progressCallback, resolve, reject)
	case "fork-security":
		enumerateADOForkSecurity(ctx, org, token, target, progressCallback, resolve, reject)
	default:
		reject.Invoke(map[string]interface{}{
			"error": fmt.Sprintf("unsupported Azure DevOps operation: %s", operation),
		})
	}
}

func enumerateADOProjects(ctx context.Context, org, token string, progressCallback ProgressCallback, resolve, reject js.Value) {
	progressCallback(20, "Enumerating ADO projects...")

	orgURL := fmt.Sprintf("https://dev.azure.com/%s", org)

	proxyBase := adoProxyBase
	transport := &adoProxyTransport{proxyBase: proxyBase}

	client := adoplatform.NewClient(orgURL, token, adoplatform.WithHTTPTransport(transport))

	projects, err := client.ListProjects(ctx)
	if err != nil {
		reject.Invoke(map[string]interface{}{"error": err.Error()})
		return
	}

	progressCallback(100, "Complete")

	jsonBytes, err := json.Marshal(map[string]interface{}{
		"projects": projects,
		"count":    len(projects),
	})
	if err != nil {
		reject.Invoke(map[string]interface{}{"error": fmt.Sprintf("failed to marshal results: %v", err)})
		return
	}

	resolve.Invoke(map[string]interface{}{
		"result": string(jsonBytes),
	})
}

func enumerateADORepos(ctx context.Context, org, token, target string, progressCallback ProgressCallback, resolve, reject js.Value) {
	progressCallback(10, "Initializing ADO client...")

	orgURL := fmt.Sprintf("https://dev.azure.com/%s", org)

	proxyBase := adoProxyBase
	transport := &adoProxyTransport{proxyBase: proxyBase}
	client := adoplatform.NewClient(orgURL, token, adoplatform.WithHTTPTransport(transport))

	var allRepos []adoplatform.Repository
	var projectCount int

	if target != "" {
		progressCallback(30, fmt.Sprintf("Enumerating repositories for project %s...", target))
		repos, err := client.ListRepositories(ctx, target)
		if err != nil {
			reject.Invoke(map[string]interface{}{"error": fmt.Sprintf("listing repositories for project %s: %v", target, err)})
			return
		}
		allRepos = repos
		projectCount = 1
	} else {
		progressCallback(20, "Listing all projects...")
		projects, err := client.ListProjects(ctx)
		if err != nil {
			reject.Invoke(map[string]interface{}{"error": fmt.Sprintf("listing projects: %v", err)})
			return
		}

		projectCount = len(projects)
		progressCallback(40, fmt.Sprintf("Enumerating repositories across %d projects...", projectCount))

		for i, project := range projects {
			repos, err := client.ListRepositories(ctx, project.Name)
			if err != nil {
				continue
			}
			allRepos = append(allRepos, repos...)

			if i%5 == 0 {
				percent := 40 + (i * 50 / len(projects))
				progressCallback(percent, fmt.Sprintf("Scanned %d/%d projects", i+1, len(projects)))
			}
		}
	}

	progressCallback(100, "Complete")

	jsonBytes, err := json.Marshal(map[string]interface{}{
		"repositories":    allRepos,
		"count":           len(allRepos),
		"projectsScanned": projectCount,
	})
	if err != nil {
		reject.Invoke(map[string]interface{}{"error": fmt.Sprintf("failed to marshal results: %v", err)})
		return
	}

	resolve.Invoke(map[string]interface{}{
		"result": string(jsonBytes),
	})
}

func enumerateADOPipelines(ctx context.Context, org, token, target string, progressCallback ProgressCallback, resolve, reject js.Value) {
	progressCallback(10, "Initializing ADO client...")

	orgURL := fmt.Sprintf("https://dev.azure.com/%s", org)
	proxyBase := adoProxyBase
	transport := &adoProxyTransport{proxyBase: proxyBase}
	client := adoplatform.NewClient(orgURL, token, adoplatform.WithHTTPTransport(transport))

	var allPipelines []adoplatform.Pipeline
	var allBuildDefs []adoplatform.BuildDefinition
	var projectCount int

	if target != "" {
		progressCallback(30, fmt.Sprintf("Enumerating pipelines for project %s...", target))

		pipelines, _ := client.ListPipelines(ctx, target)
		allPipelines = pipelines

		buildDefs, _ := client.ListBuildDefinitions(ctx, target)
		allBuildDefs = buildDefs

		projectCount = 1
	} else {
		progressCallback(20, "Listing all projects...")
		projects, err := client.ListProjects(ctx)
		if err != nil {
			reject.Invoke(map[string]interface{}{"error": fmt.Sprintf("listing projects: %v", err)})
			return
		}

		projectCount = len(projects)
		progressCallback(40, fmt.Sprintf("Enumerating pipelines across %d projects...", projectCount))

		for i, project := range projects {
			pipelines, _ := client.ListPipelines(ctx, project.Name)
			allPipelines = append(allPipelines, pipelines...)

			buildDefs, _ := client.ListBuildDefinitions(ctx, project.Name)
			allBuildDefs = append(allBuildDefs, buildDefs...)

			if i%5 == 0 {
				percent := 40 + (i * 50 / len(projects))
				progressCallback(percent, fmt.Sprintf("Scanned %d/%d projects", i+1, len(projects)))
			}
		}
	}

	progressCallback(100, "Complete")

	jsonBytes, err := json.Marshal(map[string]interface{}{
		"pipelines":        allPipelines,
		"buildDefinitions": allBuildDefs,
		"totalPipelines":   len(allPipelines),
		"totalBuildDefs":   len(allBuildDefs),
		"projectsScanned":  projectCount,
	})
	if err != nil {
		reject.Invoke(map[string]interface{}{"error": fmt.Sprintf("failed to marshal results: %v", err)})
		return
	}

	resolve.Invoke(map[string]interface{}{
		"result": string(jsonBytes),
	})
}

func enumerateADOVariables(ctx context.Context, org, token, target string, progressCallback ProgressCallback, resolve, reject js.Value) {
	if target == "" {
		reject.Invoke(map[string]interface{}{"error": "project name required for variable groups enumeration"})
		return
	}

	progressCallback(20, "Enumerating ADO variable groups...")

	orgURL := fmt.Sprintf("https://dev.azure.com/%s", org)
	proxyBase := adoProxyBase
	transport := &adoProxyTransport{proxyBase: proxyBase}
	client := adoplatform.NewClient(orgURL, token, adoplatform.WithHTTPTransport(transport))

	variableGroups, err := client.ListVariableGroups(ctx, target)
	if err != nil {
		reject.Invoke(map[string]interface{}{"error": err.Error()})
		return
	}

	progressCallback(100, "Complete")

	jsonBytes, err := json.Marshal(map[string]interface{}{
		"variableGroups": variableGroups,
		"count":          len(variableGroups),
		"project":        target,
	})
	if err != nil {
		reject.Invoke(map[string]interface{}{"error": fmt.Sprintf("failed to marshal results: %v", err)})
		return
	}

	resolve.Invoke(map[string]interface{}{
		"result": string(jsonBytes),
	})
}

func enumerateADOConnections(ctx context.Context, org, token, target string, progressCallback ProgressCallback, resolve, reject js.Value) {
	if target == "" {
		reject.Invoke(map[string]interface{}{"error": "project name required for service connections enumeration"})
		return
	}

	progressCallback(20, "Enumerating ADO service connections...")

	orgURL := fmt.Sprintf("https://dev.azure.com/%s", org)
	proxyBase := adoProxyBase
	transport := &adoProxyTransport{proxyBase: proxyBase}
	client := adoplatform.NewClient(orgURL, token, adoplatform.WithHTTPTransport(transport))

	connections, err := client.ListServiceConnections(ctx, target)
	if err != nil {
		reject.Invoke(map[string]interface{}{"error": err.Error()})
		return
	}

	progressCallback(100, "Complete")

	jsonBytes, err := json.Marshal(map[string]interface{}{
		"connections": connections,
		"count":       len(connections),
		"project":     target,
	})
	if err != nil {
		reject.Invoke(map[string]interface{}{"error": fmt.Sprintf("failed to marshal results: %v", err)})
		return
	}

	resolve.Invoke(map[string]interface{}{
		"result": string(jsonBytes),
	})
}

func enumerateADOAgentPools(ctx context.Context, org, token string, progressCallback ProgressCallback, resolve, reject js.Value) {
	progressCallback(20, "Enumerating ADO agent pools...")

	orgURL := fmt.Sprintf("https://dev.azure.com/%s", org)

	proxyBase := adoProxyBase
	transport := &adoProxyTransport{proxyBase: proxyBase}
	client := adoplatform.NewClient(orgURL, token, adoplatform.WithHTTPTransport(transport))

	pools, err := client.ListAgentPools(ctx)
	if err != nil {
		reject.Invoke(map[string]interface{}{"error": err.Error()})
		return
	}

	progressCallback(100, "Complete")

	jsonBytes, err := json.Marshal(map[string]interface{}{
		"pools": pools,
		"count": len(pools),
	})
	if err != nil {
		reject.Invoke(map[string]interface{}{"error": fmt.Sprintf("failed to marshal results: %v", err)})
		return
	}

	resolve.Invoke(map[string]interface{}{
		"result": string(jsonBytes),
	})
}

func enumerateADOAttackPaths(ctx context.Context, org, token, target string, progressCallback ProgressCallback, resolve, reject js.Value) {
	progressCallback(20, "Analyzing ADO attack paths...")

	// Not implemented in WASM -- requires permission analysis, trigger inspection,
	// and policy correlation that are only available via the CLI.
	progressCallback(100, "Complete")

	result := map[string]interface{}{
		"message": "Attack path analysis is a complex operation that requires the CLI for full functionality. Use: trajan ado enumerate attack-paths --org " + org,
		"note":    "This operation analyzes permissions, triggers, and policies to identify exploitation paths.",
	}

	if target != "" {
		result["message"] = "Attack path analysis for project: " + target + ". Full analysis requires CLI: trajan ado enumerate attack-paths --org " + org + " --project " + target
	}

	jsonBytes, err := json.Marshal(result)
	if err != nil {
		reject.Invoke(map[string]interface{}{"error": fmt.Sprintf("failed to marshal results: %v", err)})
		return
	}

	resolve.Invoke(map[string]interface{}{
		"result": string(jsonBytes),
	})
}

func enumerateADOForkSecurity(ctx context.Context, org, token, target string, progressCallback ProgressCallback, resolve, reject js.Value) {
	progressCallback(20, "Scanning ADO fork security...")

	// Not implemented in WASM -- requires deep build-definition scanning,
	// trigger analysis, and secret-exposure detection only available via CLI.
	progressCallback(100, "Complete")

	result := map[string]interface{}{
		"message": "Fork security scanning is a complex operation that requires the CLI. Use: trajan ado enumerate fork-security --org " + org,
		"note":    "This operation scans GitHub/GitHubEnterprise repositories in pipelines for fork build vulnerabilities.",
	}

	if target != "" {
		result["message"] = "Fork security scan for project: " + target + ". Full scan requires CLI: trajan ado enumerate fork-security --org " + org + " --project " + target
	}

	jsonBytes, err := json.Marshal(result)
	if err != nil {
		reject.Invoke(map[string]interface{}{"error": fmt.Sprintf("failed to marshal results: %v", err)})
		return
	}

	resolve.Invoke(map[string]interface{}{
		"result": string(jsonBytes),
	})
}

// Search performs code search using GitHub or SourceGraph
//
// JavaScript signature:
//
//	async function trajanSearch(query: string, options: {
//	  token: string,
//	  source?: "github" | "sourcegraph",
//	  org?: string
//	}): Promise<{result: string, error?: string}>
func Search(this js.Value, args []js.Value) interface{} {
	if len(args) < 2 {
		return js.ValueOf(map[string]interface{}{
			"error": "missing required arguments: query and options",
		})
	}

	query := args[0].String()
	options := args[1]

	handler := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		resolve := args[0]
		reject := args[1]

		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()

			source := "github"
			if !options.Get("source").IsUndefined() {
				source = options.Get("source").String()
			}

			org := ""
			if !options.Get("org").IsUndefined() {
				org = options.Get("org").String()
			}

			if query == "" {
				query = search.DefaultSelfHostedQuery(org)
			}

			var searchResult *search.SearchResult
			var err error

			switch source {
			case "github":
				token := options.Get("token").String()
				if token == "" {
					reject.Invoke(map[string]interface{}{"error": "token required for GitHub search"})
					return
				}

				provider := search.NewGitHubSearchProvider(http.DefaultClient, token)
				searchResult, err = provider.Search(ctx, query)

			case "sourcegraph":
				provider := search.NewSourceGraphSearchProvider("")
				searchResult, err = provider.Search(ctx, query)

			default:
				reject.Invoke(map[string]interface{}{"error": fmt.Sprintf("unsupported source: %s", source)})
				return
			}

			if err != nil {
				reject.Invoke(map[string]interface{}{"error": fmt.Sprintf("search failed: %v", err)})
				return
			}

			result := map[string]interface{}{
				"repositories": searchResult.Repositories,
				"totalCount":   searchResult.TotalCount,
				"incomplete":   searchResult.Incomplete,
			}

			resultJSON, err := json.Marshal(result)
			if err != nil {
				reject.Invoke(map[string]interface{}{"error": fmt.Sprintf("marshal failed: %v", err)})
				return
			}

			resolve.Invoke(map[string]interface{}{"result": string(resultJSON)})
		}()

		return nil
	})

	promiseConstructor := js.Global().Get("Promise")
	return promiseConstructor.New(handler)
}

// registerFunctions registers all exported functions to the global JavaScript scope
func registerFunctions() {
	js.Global().Set("trajanInitialize", js.FuncOf(Initialize))
	js.Global().Set("trajanStartScan", js.FuncOf(StartScan))
	js.Global().Set("trajanGetResults", js.FuncOf(GetResults))
	js.Global().Set("trajanExportResults", js.FuncOf(ExportResults))
	js.Global().Set("trajanExecuteAttack", js.FuncOf(ExecuteAttack))
	js.Global().Set("trajanCleanupSession", js.FuncOf(CleanupSession))
	js.Global().Set("trajanGetSessionStatus", js.FuncOf(GetSessionStatus))
	js.Global().Set("trajanListAttackPlugins", js.FuncOf(ListAttackPlugins))
	js.Global().Set("trajanListSessions", js.FuncOf(ListSessions))
	js.Global().Set("trajanConfigSet", js.FuncOf(ConfigSet))
	js.Global().Set("trajanConfigGet", js.FuncOf(ConfigGet))
	js.Global().Set("trajanCancelScan", js.FuncOf(CancelScan))

	js.Global().Set("trajanValidateToken", js.FuncOf(ValidateToken))
	js.Global().Set("trajanScanSecrets", js.FuncOf(ScanSecrets))
	js.Global().Set("trajanScanRunners", js.FuncOf(ScanRunners))
	js.Global().Set("trajanSelfEnumerate", js.FuncOf(SelfEnumerate))
	js.Global().Set("trajanEnumerate", js.FuncOf(Enumerate))
	js.Global().Set("trajanSearch", js.FuncOf(Search))

	fmt.Println("Trajan WASM API initialized successfully")
}
