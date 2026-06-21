//go:build js && wasm
// +build js,wasm

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

	yaml "gopkg.in/yaml.v3"

	"github.com/praetorian-inc/trajan/internal/registry"
	"github.com/praetorian-inc/trajan/pkg/analysis"
	"github.com/praetorian-inc/trajan/pkg/analysis/graph"
	"github.com/praetorian-inc/trajan/pkg/analysis/parser"
	"github.com/praetorian-inc/trajan/pkg/attacks"
	adoplatform "github.com/praetorian-inc/trajan/pkg/azuredevops"
	"github.com/praetorian-inc/trajan/pkg/azuredevops/tokenprobe"
	"github.com/praetorian-inc/trajan/pkg/config"
	"github.com/praetorian-inc/trajan/pkg/detections"
	"github.com/praetorian-inc/trajan/pkg/github"
	gitlabplatform "github.com/praetorian-inc/trajan/pkg/gitlab"
	"github.com/praetorian-inc/trajan/pkg/platforms"
	"github.com/praetorian-inc/trajan/pkg/scanner"
	"github.com/praetorian-inc/trajan/pkg/search"
	"github.com/praetorian-inc/trajan/pkg/storage"

	// Import attack plugins for init() auto-registration
	_ "github.com/praetorian-inc/trajan/pkg/github/attacks/c2setup"
	_ "github.com/praetorian-inc/trajan/pkg/github/attacks/interactiveshell"
	_ "github.com/praetorian-inc/trajan/pkg/github/attacks/persistence"
	_ "github.com/praetorian-inc/trajan/pkg/github/attacks/prattack"
	_ "github.com/praetorian-inc/trajan/pkg/github/attacks/runneronrunner"
	_ "github.com/praetorian-inc/trajan/pkg/github/attacks/secretsdump"
	_ "github.com/praetorian-inc/trajan/pkg/github/attacks/workflowinjection"

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

func isGitHubHostedRunner(label string) bool {
	return parser.GitHubHostedRunners[label]
}

type workflowYAML struct {
	On   interface{} `yaml:"on"`
	Jobs map[string]struct {
		RunsOn interface{} `yaml:"runs-on"`
	} `yaml:"jobs"`
}

func extractSelfHostedJobs(workflowContent []byte) []map[string]interface{} {
	var wf workflowYAML
	if err := yaml.Unmarshal(workflowContent, &wf); err != nil {
		return nil
	}

	var selfHostedJobs []map[string]interface{}
	for jobName, job := range wf.Jobs {
		var labels []string

		switch v := job.RunsOn.(type) {
		case string:
			labels = []string{v}
		case []interface{}:
			for _, label := range v {
				if s, ok := label.(string); ok {
					labels = append(labels, s)
				}
			}
		}

		isSelfHosted := false
		for _, label := range labels {
			if !isGitHubHostedRunner(label) {
				isSelfHosted = true
				break
			}
		}

		if isSelfHosted {
			selfHostedJobs = append(selfHostedJobs, map[string]interface{}{
				"job":    jobName,
				"labels": labels,
			})
		}
	}

	return selfHostedJobs
}

func extractTriggers(workflowContent []byte) []string {
	var wf workflowYAML
	if err := yaml.Unmarshal(workflowContent, &wf); err != nil {
		return []string{}
	}

	var triggers []string
	switch v := wf.On.(type) {
	case string:
		triggers = []string{v}
	case []interface{}:
		for _, t := range v {
			if s, ok := t.(string); ok {
				triggers = append(triggers, s)
			}
		}
	case map[string]interface{}:
		for key := range v {
			triggers = append(triggers, key)
		}
	}

	return triggers
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
				if scope == "org" || scope == "user" {
					reportProgress(5, "Connecting to GitHub API...")
					client := github.NewClient(github.DefaultBaseURL, token)

					reportProgress(8, fmt.Sprintf("Enumerating %s repositories...", target))
					var repos []github.Repository
					var listErr error
					if scope == "org" {
						repos, listErr = client.ListOrgRepos(ctx, target)
					} else {
						repos, listErr = client.ListUserRepos(ctx, target)
					}
					if listErr != nil {
						reject.Invoke(map[string]interface{}{"error": fmt.Sprintf("listing repos: %v", listErr)})
						return
					}
					reportProgress(15, fmt.Sprintf("Found %d repositories, fetching workflows...", len(repos)))

					scanResult := &platforms.ScanResult{
						Workflows: make(map[string][]platforms.Workflow),
					}
					for _, r := range repos {
						scanResult.Repositories = append(scanResult.Repositories, platforms.Repository{
							Owner: r.Owner.Login, Name: r.Name,
							DefaultBranch: r.DefaultBranch, Private: r.Private,
							Archived: r.Archived, URL: r.HTMLURL,
						})
					}

					totalWF := 0
					for i, repo := range repos {
						pct := 15 + int(float64(i)/float64(len(repos))*35) // 15-50%
						reportProgress(pct, fmt.Sprintf("[%d/%d] %s/%s...", i+1, len(repos), repo.Owner.Login, repo.Name))

						files, err := client.GetWorkflowFiles(ctx, repo.Owner.Login, repo.Name)
						if err != nil {
							continue
						}

						var workflows []platforms.Workflow
						for _, f := range files {
							content, err := client.GetWorkflowContent(ctx, repo.Owner.Login, repo.Name, f.Path)
							if err != nil {
								continue
							}
							workflows = append(workflows, platforms.Workflow{
								Name: f.Name, Path: f.Path, Content: content, SHA: f.SHA,
								RepoSlug: fmt.Sprintf("%s/%s", repo.Owner.Login, repo.Name),
							})
						}
						if len(workflows) > 0 {
							scanResult.Workflows[repo.FullName] = workflows
							totalWF += len(workflows)
						}
					}
					reportProgress(50, fmt.Sprintf("Found %d workflows across %d repos, parsing...", totalWF, len(repos)))

					ghParser := parser.GetParser("github")
					if ghParser == nil {
						scanErr = fmt.Errorf("GitHub parser not registered")
						reject.Invoke(map[string]interface{}{"error": scanErr.Error()})
						return
					}

					type workflowWithRepo struct {
						workflow *parser.NormalizedWorkflow
						repoSlug string
					}
					var parsedWorkflows []workflowWithRepo
					for repoSlug, workflows := range scanResult.Workflows {
						for _, wf := range workflows {
							normalized, err := ghParser.Parse(wf.Content)
							if err != nil {
								fmt.Printf("Failed to parse workflow %s: %v\n", wf.Path, err)
								continue
							}
							normalized.Path = wf.Path
							parsedWorkflows = append(parsedWorkflows, workflowWithRepo{
								workflow: normalized,
								repoSlug: repoSlug,
							})
						}
					}

					reportProgress(60, fmt.Sprintf("Parsed %d workflows, building graphs...", len(parsedWorkflows)))

					graphs := make(map[string]*graph.Graph)
					for _, pair := range parsedWorkflows {
						g, err := analysis.BuildGraphFromNormalized(pair.repoSlug, pair.workflow.Path, pair.workflow)
						if err != nil {
							fmt.Printf("Failed to build graph for workflow %s: %v\n", pair.workflow.Path, err)
							continue
						}
						graphKey := fmt.Sprintf("%s/%s", pair.repoSlug, pair.workflow.Path)
						graphs[graphKey] = g
					}

					reportProgress(70, fmt.Sprintf("Built %d graphs, running detectors...", len(graphs)))

					detectorRegistry := registry.GetDetections("github")

					seen := make(map[string]bool)

					for path, g := range graphs {
						for _, detector := range detectorRegistry {
							detectorFindings, err := detector.Detect(ctx, g)
							if err != nil {
								fmt.Printf("Detector %s failed on workflow %s: %v\n", detector.Name(), path, err)
								continue
							}

							for _, finding := range detectorFindings {
								key := fmt.Sprintf("%s|%s|%s|%s|%s",
									finding.Workflow,
									finding.Job,
									finding.Step,
									finding.Type,
									finding.Evidence)

								if !seen[key] {
									seen[key] = true
									findings = append(findings, finding)
								}
							}
						}
					}

					for i := range findings {
						for repoSlug, workflows := range scanResult.Workflows {
							if findings[i].Repository == repoSlug || findings[i].Repository == strings.TrimPrefix(repoSlug, "https://github.com/") {
								for _, wf := range workflows {
									if findings[i].Workflow == wf.Path || findings[i].Workflow == wf.Name {
										findings[i].WorkflowContent = string(wf.Content)
										break
									}
								}
							}
						}
					}

					scanErr = nil
					reportProgress(100, fmt.Sprintf("Scan complete - %d repos, %d vulnerabilities", len(scanResult.Repositories), len(findings)))
				} else {
					client := github.NewClient(github.DefaultBaseURL, token)

					reportProgress(20, "Parsing repository URL...")
					parts := strings.Split(strings.TrimPrefix(target, "https://github.com/"), "/")
					if len(parts) < 2 {
						scanErr = fmt.Errorf("invalid GitHub repository URL: %s", target)
						reject.Invoke(map[string]interface{}{"error": scanErr.Error()})
						return
					}
					owner, repo := parts[0], parts[1]

					reportProgress(30, "Fetching workflow files...")
					workflows, err := client.GetWorkflowFiles(ctx, owner, repo)
					if err != nil {
						scanErr = fmt.Errorf("failed to fetch workflows: %w", err)
						reject.Invoke(map[string]interface{}{"error": scanErr.Error()})
						return
					}

					if len(workflows) == 0 {
						reportProgress(100, "No workflows found - scan complete")
						findings = []detections.Finding{}
						scanErr = nil
					} else {
						reportProgress(50, fmt.Sprintf("Parsing %d workflow files...", len(workflows)))

						ghParser := parser.GetParser("github")
						if ghParser == nil {
							scanErr = fmt.Errorf("GitHub parser not registered")
							reject.Invoke(map[string]interface{}{"error": scanErr.Error()})
							return
						}

						var parsedWorkflows []*parser.NormalizedWorkflow
						for _, wf := range workflows {
							content, err := client.GetWorkflowContent(ctx, owner, repo, wf.Path)
							if err != nil {
								fmt.Printf("Failed to get workflow %s: %v\n", wf.Path, err)
								continue
							}

							normalized, err := ghParser.Parse(content)
							if err != nil {
								fmt.Printf("Failed to parse workflow %s: %v\n", wf.Path, err)
								continue
							}

							normalized.Path = wf.Path
							parsedWorkflows = append(parsedWorkflows, normalized)
						}

						reportProgress(70, fmt.Sprintf("Parsed %d workflows, building graphs...", len(parsedWorkflows)))

						graphs := make(map[string]*graph.Graph)
						for _, wf := range parsedWorkflows {
							g, err := analysis.BuildGraphFromNormalized(fmt.Sprintf("%s/%s", owner, repo), wf.Path, wf)
							if err != nil {
								fmt.Printf("Failed to build graph for workflow %s: %v\n", wf.Path, err)
								continue
							}
							graphs[wf.Path] = g
						}

						reportProgress(75, fmt.Sprintf("Built %d graphs, running detectors...", len(graphs)))

						detectorRegistry := registry.GetDetections("github")

						seen := make(map[string]bool)

						for path, g := range graphs {
							for _, detector := range detectorRegistry {
								detectorFindings, err := detector.Detect(ctx, g)
								if err != nil {
									fmt.Printf("Detector %s failed on workflow %s: %v\n", detector.Name(), path, err)
									continue
								}

								for _, finding := range detectorFindings {
									key := fmt.Sprintf("%s|%s|%s|%s|%s",
										finding.Workflow,
										finding.Job,
										finding.Step,
										finding.Type,
										finding.Evidence)

									if !seen[key] {
										seen[key] = true
										findings = append(findings, finding)
									}
								}
							}
						}

						workflowContentCache := make(map[string][]byte)
						for _, wf := range workflows {
							content, err := client.GetWorkflowContent(ctx, owner, repo, wf.Path)
							if err == nil {
								workflowContentCache[wf.Path] = content
							}
						}

						for i := range findings {
							if content, ok := workflowContentCache[findings[i].Workflow]; ok {
								findings[i].WorkflowContent = string(content)
							}
						}

						scanErr = nil
						reportProgress(100, fmt.Sprintf("Scan complete - found %d vulnerabilities", len(findings)))
					}
				}

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

	pluginName := args[0].String()
	target := args[1].String()
	options := args[2]

	handler := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		resolve := args[0]
		reject := args[1]

		go func() {
			ctx := context.Background()

			// CRITICAL: Verify authorization
			if !options.Get("authorized").Bool() {
				reject.Invoke(map[string]interface{}{
					"error": "attack execution requires explicit authorization (set authorized: true)",
				})
				return
			}

			plugin, err := registry.GetAttackPluginByName(registry.PluginKey(platforms.PlatformGitHub, pluginName))
			if err != nil {
				reject.Invoke(map[string]interface{}{
					"error": fmt.Sprintf("unknown attack plugin: %v", err),
				})
				return
			}

			targetValue := strings.TrimPrefix(target, "https://github.com/")
			parts := strings.Split(targetValue, "/")
			if len(parts) < 2 {
				reject.Invoke(map[string]interface{}{
					"error": fmt.Sprintf("invalid GitHub repository URL: %s", target),
				})
				return
			}

			token := options.Get("token").String()
			ghPlatform := github.NewPlatform()
			if err := ghPlatform.Init(ctx, platforms.Config{
				Token:   token,
				BaseURL: github.DefaultBaseURL,
			}); err != nil {
				reject.Invoke(map[string]interface{}{
					"error": fmt.Sprintf("failed to initialize GitHub platform: %v", err),
				})
				return
			}

			attackOpts := attacks.AttackOptions{
				Target: platforms.Target{
					Type:  platforms.TargetRepo,
					Value: targetValue, // "owner/repo"
				},
				Platform:  ghPlatform,
				DryRun:    false,
				Verbose:   true,
				SessionID: fmt.Sprintf("session_%d", time.Now().UnixNano()),
				ExtraOpts: make(map[string]string),
			}

			if !options.Get("dryRun").IsUndefined() {
				attackOpts.DryRun = options.Get("dryRun").Bool()
			}
			if !options.Get("branch").IsUndefined() {
				attackOpts.Branch = options.Get("branch").String()
			}
			if !options.Get("payload").IsUndefined() {
				attackOpts.Payload = options.Get("payload").String()
			}

			var progressCallback js.Value
			if !options.Get("onProgress").IsUndefined() {
				progressCallback = options.Get("onProgress")
			}

			reportProgress := func(message string) {
				if !progressCallback.IsUndefined() && !progressCallback.IsNull() {
					progressCallback.Invoke(message)
				}
			}

			reportProgress(fmt.Sprintf("Executing %s attack on %s...", pluginName, target))

			result, err := plugin.Execute(ctx, attackOpts)
			if err != nil {
				reject.Invoke(map[string]interface{}{
					"error": fmt.Sprintf("attack execution failed: %v", err),
				})
				return
			}

			reportProgress("Attack execution complete")

			saveSession := true
			if !options.Get("saveSession").IsUndefined() {
				saveSession = options.Get("saveSession").Bool()
			}

			if attackOpts.DryRun {
				saveSession = false
			}

			if saveSession {
				session := &storage.Session{
					ID:        result.SessionID,
					Plugin:    result.Plugin,
					Target:    targetValue, // Store as "owner/repo"
					Status:    "completed", // Map from result.Success
					CreatedAt: result.Timestamp,
					UpdatedAt: time.Now(),
					Metadata: map[string]interface{}{
						"token":    token,    // Store token for cleanup
						"platform": "github", // Store platform for cleanup lookup
					},
				}

				for _, artifact := range result.Artifacts {
					session.Artifacts = append(session.Artifacts, storage.Artifact{
						Type: string(artifact.Type),
						ID:   artifact.Identifier,
						URL:  artifact.URL,
						Metadata: map[string]interface{}{
							"description": artifact.Description,
						},
					})
				}

				for _, action := range result.CleanupActions {
					session.CleanupActions = append(session.CleanupActions, storage.CleanupAction{
						Type: string(action.Type),
						Params: map[string]interface{}{
							"identifier":  action.Identifier,
							"action":      action.Action,
							"description": action.Description,
						},
					})
				}

				if err := globalStorage.SaveSession(ctx, session); err != nil {
					fmt.Printf("failed to save session: %v\n", err)
				}

				reportProgress("Session saved for later cleanup")
			}

			resultJSON, err := json.Marshal(result)
			if err != nil {
				reject.Invoke(map[string]interface{}{
					"error": fmt.Sprintf("failed to serialize result: %v", err),
				})
				return
			}

			resolve.Invoke(map[string]interface{}{
				"result": string(resultJSON),
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

	sessionID := args[0].String()
	token := args[1].String() // Token from UI cleanup form

	handler := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		resolve := args[0]
		reject := args[1]

		go func() {
			ctx := context.Background()

			storageSession, err := globalStorage.LoadSession(ctx, sessionID)
			if err != nil {
				reject.Invoke(map[string]interface{}{
					"error": fmt.Sprintf("failed to load session: %v", err),
				})
				return
			}

			sessionPlatform := "github"
			if p, ok := storageSession.Metadata["platform"].(string); ok {
				sessionPlatform = p
			}
			plugin, err := registry.GetAttackPluginByName(registry.PluginKey(sessionPlatform, storageSession.Plugin))
			if err != nil {
				reject.Invoke(map[string]interface{}{
					"error": fmt.Sprintf("unknown attack plugin: %v", err),
				})
				return
			}

			sessionToken := token
			if sessionToken == "" {
				if savedToken, ok := storageSession.Metadata["token"].(string); ok {
					sessionToken = savedToken
				}
			}

			ghPlatform := github.NewPlatform()
			err = ghPlatform.Init(ctx, platforms.Config{
				Token:   sessionToken,
				BaseURL: github.DefaultBaseURL,
			})
			if err != nil {
				reject.Invoke(map[string]interface{}{
					"error": fmt.Sprintf("failed to initialize GitHub platform: %v", err),
				})
				return
			}

			upstreamSession := &attacks.Session{
				ID: storageSession.ID,
				Target: platforms.Target{
					Type:  platforms.TargetRepo,
					Value: storageSession.Target, // Already in "owner/repo" format
				},
				CreatedAt: storageSession.CreatedAt,
				Results:   make([]*attacks.AttackResult, 0),
				Platform:  ghPlatform,
			}

			result := &attacks.AttackResult{
				Plugin:    storageSession.Plugin,
				SessionID: storageSession.ID,
				Timestamp: storageSession.CreatedAt,
				Success:   storageSession.Status == "completed",
			}

			for _, artifact := range storageSession.Artifacts {
				result.Artifacts = append(result.Artifacts, attacks.Artifact{
					Type:        attacks.ArtifactType(artifact.Type),
					Identifier:  artifact.ID,
					URL:         artifact.URL,
					Description: artifact.Metadata["description"].(string),
				})
			}

			for _, action := range storageSession.CleanupActions {
				result.CleanupActions = append(result.CleanupActions, attacks.CleanupAction{
					Type:        attacks.ArtifactType(action.Type),
					Identifier:  action.Params["identifier"].(string),
					Action:      action.Params["action"].(string),
					Description: action.Params["description"].(string),
				})
			}

			upstreamSession.Results = append(upstreamSession.Results, result)

			err = plugin.Cleanup(ctx, upstreamSession)
			if err != nil {
				reject.Invoke(map[string]interface{}{
					"error": fmt.Sprintf("cleanup failed: %v", err),
				})
				return
			}

			if err := globalStorage.DeleteSession(ctx, sessionID); err != nil {
				fmt.Printf("failed to delete session: %v\n", err)
			}

			cleanupSummary := map[string]interface{}{
				"session_id":        sessionID,
				"plugin":            storageSession.Plugin,
				"artifacts_cleaned": len(result.Artifacts),
				"success":           true,
			}

			summaryJSON, err := json.Marshal(cleanupSummary)
			if err != nil {
				reject.Invoke(map[string]interface{}{
					"error": fmt.Sprintf("failed to serialize cleanup summary: %v", err),
				})
				return
			}

			resolve.Invoke(map[string]interface{}{
				"summary": string(summaryJSON),
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

			token := globalConfig.GitHub.Token
			if !options.Get("token").IsUndefined() {
				optToken := options.Get("token").String()
				if optToken != "" {
					token = optToken
				}
			}

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
				validateGitHubToken(ctx, token, resolve, reject)
			}
		}()

		return nil
	})

	promiseConstructor := js.Global().Get("Promise")
	return promiseConstructor.New(handler)
}

func validateGitHubToken(ctx context.Context, token string, resolve, reject js.Value) {
	ghPlatform := github.NewPlatform()
	if err := ghPlatform.Init(ctx, platforms.Config{Token: token, BaseURL: github.DefaultBaseURL}); err != nil {
		reject.Invoke(map[string]interface{}{"error": fmt.Sprintf("init failed: %v", err)})
		return
	}

	tokenInfoResult, err := ghPlatform.ScanTokenInfo(ctx)
	if err != nil {
		reject.Invoke(map[string]interface{}{"error": fmt.Sprintf("token scan failed: %v", err)})
		return
	}

	if tokenInfoResult.TokenInfo == nil {
		reject.Invoke(map[string]interface{}{"error": "no token info returned"})
		return
	}

	orgs, err := ghPlatform.Client().ListAuthenticatedUserOrgs(ctx)
	if err != nil {
		reject.Invoke(map[string]interface{}{"error": fmt.Sprintf("list orgs failed: %v", err)})
		return
	}

	expirationStr := ""
	if tokenInfoResult.TokenInfo.Expiration != nil {
		expirationStr = tokenInfoResult.TokenInfo.Expiration.Format("2006-01-02 15:04:05 MST")
	}

	result := map[string]interface{}{
		"user": map[string]interface{}{
			"login": tokenInfoResult.TokenInfo.User,
			"name":  tokenInfoResult.TokenInfo.Name,
		},
		"scopes":     tokenInfoResult.TokenInfo.Scopes,
		"token_type": string(tokenInfoResult.TokenInfo.Type),
		"expiration": expirationStr,
		"orgs":       orgs,
	}

	resultJSON, err := json.Marshal(result)
	if err != nil {
		reject.Invoke(map[string]interface{}{"error": fmt.Sprintf("marshal failed: %v", err)})
		return
	}

	resolve.Invoke(map[string]interface{}{"result": string(resultJSON)})
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

// ScanSecrets scans an organization for secrets
//
// JavaScript signature:
//
//	async function trajanScanSecrets(target: string, options: {
//	  token: string,
//	  onProgress?: (percent: number, message: string) => void
//	}): Promise<{result: string, error?: string}>
func ScanSecrets(this js.Value, args []js.Value) interface{} {
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
			ctx := context.Background()

			token := options.Get("token").String()
			if token == "" {
				reject.Invoke(map[string]interface{}{"error": "token required"})
				return
			}

			var progressCallback js.Value
			if !options.Get("onProgress").IsUndefined() {
				progressCallback = options.Get("onProgress")
			}

			reportProgress := func(percent int, message string) {
				if !progressCallback.IsUndefined() && !progressCallback.IsNull() {
					progressCallback.Invoke(percent, message)
				}
			}

			reportProgress(10, "Initializing client...")

			client := github.NewClient(github.DefaultBaseURL, token)

			reportProgress(20, "Fetching org secrets...")

			orgSecrets, err := client.ListOrgActionsSecrets(ctx, target)
			if err != nil {
				reject.Invoke(map[string]interface{}{"error": fmt.Sprintf("list org secrets failed: %v", err)})
				return
			}

			reportProgress(30, "Fetching org variables...")

			orgVariables, err := client.ListOrgActionsVariables(ctx, target)
			if err != nil {
				reject.Invoke(map[string]interface{}{"error": fmt.Sprintf("list org variables failed: %v", err)})
				return
			}

			reportProgress(40, "Fetching repositories...")

			repos, err := client.ListOrgRepos(ctx, target)
			if err != nil {
				reject.Invoke(map[string]interface{}{"error": fmt.Sprintf("list repos failed: %v", err)})
				return
			}

			reportProgress(50, fmt.Sprintf("Scanning %d repositories...", len(repos)))

			repoResults := make([]map[string]interface{}, 0)
			for i, repo := range repos {
				repoSecrets, _ := client.ListRepoActionsSecrets(ctx, repo.Owner.Login, repo.Name)
				repoOrgSecrets, _ := client.ListRepoOrgSecrets(ctx, repo.Owner.Login, repo.Name)
				repoVariables, _ := client.ListRepoActionsVariables(ctx, repo.Owner.Login, repo.Name)

				repoResults = append(repoResults, map[string]interface{}{
					"name":       repo.FullName,
					"private":    repo.Private,
					"archived":   repo.Archived,
					"secrets":    repoSecrets,
					"orgSecrets": repoOrgSecrets,
					"variables":  repoVariables,
				})

				if i%10 == 0 {
					percent := 50 + (i * 40 / len(repos))
					reportProgress(percent, fmt.Sprintf("Scanned %d/%d repositories", i, len(repos)))
				}
			}

			totalSecrets := len(orgSecrets)
			for _, r := range repoResults {
				totalSecrets += len(r["secrets"].([]github.Secret))
				totalSecrets += len(r["orgSecrets"].([]github.Secret))
			}

			result := map[string]interface{}{
				"org":          target,
				"orgSecrets":   orgSecrets,
				"orgVariables": orgVariables,
				"repos":        repoResults,
				"totalSecrets": totalSecrets,
				"totalRepos":   len(repos),
			}

			resultJSON, err := json.Marshal(result)
			if err != nil {
				reject.Invoke(map[string]interface{}{"error": fmt.Sprintf("marshal failed: %v", err)})
				return
			}

			reportProgress(100, fmt.Sprintf("Scan complete - %d secrets across %d repos", totalSecrets, len(repos)))

			resolve.Invoke(map[string]interface{}{"result": string(resultJSON)})
		}()

		return nil
	})

	promiseConstructor := js.Global().Get("Promise")
	return promiseConstructor.New(handler)
}

// ScanRunners scans an organization for self-hosted runners
//
// JavaScript signature:
//
//	async function trajanScanRunners(target: string, options: {
//	  token: string,
//	  onProgress?: (percent: number, message: string) => void
//	}): Promise<{result: string, error?: string}>
func ScanRunners(this js.Value, args []js.Value) interface{} {
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
			ctx := context.Background()

			token := options.Get("token").String()
			if token == "" {
				reject.Invoke(map[string]interface{}{"error": "token required"})
				return
			}

			var progressCallback js.Value
			if !options.Get("onProgress").IsUndefined() {
				progressCallback = options.Get("onProgress")
			}

			reportProgress := func(percent int, message string) {
				if !progressCallback.IsUndefined() && !progressCallback.IsNull() {
					progressCallback.Invoke(percent, message)
				}
			}

			reportProgress(10, "Fetching org runners...")

			client := github.NewClient(github.DefaultBaseURL, token)

			orgRunners, err := client.ListOrgRunners(ctx, target)
			if err != nil {
				reject.Invoke(map[string]interface{}{"error": fmt.Sprintf("list runners failed: %v", err)})
				return
			}

			reportProgress(20, "Fetching repositories...")

			repos, err := client.ListOrgRepos(ctx, target)
			if err != nil {
				reject.Invoke(map[string]interface{}{"error": fmt.Sprintf("list repos failed: %v", err)})
				return
			}

			reportProgress(30, fmt.Sprintf("Scanning %d repositories for workflows...", len(repos)))

			repoRunners := make([]map[string]interface{}, 0)
			workflows := make([]map[string]interface{}, 0)

			for i, repo := range repos {
				runners, _ := client.ListRepoRunners(ctx, repo.Owner.Login, repo.Name)
				if len(runners) > 0 {
					repoRunners = append(repoRunners, map[string]interface{}{
						"repo":    repo.FullName,
						"runners": runners,
					})
				}

				workflowFiles, err := client.GetWorkflowFiles(ctx, repo.Owner.Login, repo.Name)
				if err != nil {
					continue
				}

				for _, wf := range workflowFiles {
					content, err := client.GetWorkflowContent(ctx, repo.Owner.Login, repo.Name, wf.Path)
					if err != nil {
						continue
					}

					selfHostedJobs := extractSelfHostedJobs(content)
					if len(selfHostedJobs) > 0 {
						triggers := extractTriggers(content)
						workflows = append(workflows, map[string]interface{}{
							"repo":           repo.FullName,
							"file":           wf.Name,
							"private":        repo.Private,
							"url":            fmt.Sprintf("https://github.com/%s/blob/%s/%s", repo.FullName, repo.DefaultBranch, wf.Path),
							"selfHostedJobs": selfHostedJobs,
							"triggers":       triggers,
						})
					}
				}

				if i%10 == 0 {
					percent := 30 + (i * 60 / len(repos))
					reportProgress(percent, fmt.Sprintf("Scanned %d/%d repositories", i, len(repos)))
				}
			}

			result := map[string]interface{}{
				"org":            target,
				"runners":        orgRunners,
				"repoRunners":    repoRunners,
				"workflows":      workflows,
				"totalWorkflows": len(workflows),
				"totalRepos":     len(repos),
			}

			resultJSON, err := json.Marshal(result)
			if err != nil {
				reject.Invoke(map[string]interface{}{"error": fmt.Sprintf("marshal failed: %v", err)})
				return
			}

			reportProgress(100, fmt.Sprintf("Scan complete - %d workflows with self-hosted runners", len(workflows)))

			resolve.Invoke(map[string]interface{}{"result": string(resultJSON)})
		}()

		return nil
	})

	promiseConstructor := js.Global().Get("Promise")
	return promiseConstructor.New(handler)
}

// SelfEnumerate performs comprehensive token enumeration
//
// JavaScript signature:
//
//	async function trajanSelfEnumerate(options: {
//	  token: string,
//	  onProgress?: (percent: number, message: string) => void
//	}): Promise<{result: string, error?: string}>
func SelfEnumerate(this js.Value, args []js.Value) interface{} {
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

			token := options.Get("token").String()
			if token == "" {
				reject.Invoke(map[string]interface{}{"error": "token required"})
				return
			}

			var progressCallback js.Value
			if !options.Get("onProgress").IsUndefined() {
				progressCallback = options.Get("onProgress")
			}

			reportProgress := func(percent int, message string) {
				if !progressCallback.IsUndefined() && !progressCallback.IsNull() {
					progressCallback.Invoke(percent, message)
				}
			}

			reportProgress(10, "Validating token...")

			client := github.NewClient(github.DefaultBaseURL, token)

			tokenInfo, err := client.GetTokenInfo(ctx)
			if err != nil {
				reject.Invoke(map[string]interface{}{"error": fmt.Sprintf("get token info failed: %v", err)})
				return
			}

			reportProgress(20, "Enumerating organizations...")

			orgs, err := client.ListAuthenticatedUserOrgs(ctx)
			if err != nil {
				reject.Invoke(map[string]interface{}{"error": fmt.Sprintf("list orgs failed: %v", err)})
				return
			}

			reportProgress(30, fmt.Sprintf("Analyzing %d organizations...", len(orgs)))

			orgResults := make([]map[string]interface{}, 0)
			reposWithRunners := make([]map[string]interface{}, 0)

			for i, org := range orgs {
				orgDetail, err := client.GetOrgDetails(ctx, org.Login)
				isAdmin := false
				sso := false
				if err == nil {
					isAdmin = orgDetail.BillingEmail != ""
					sso = orgDetail.TwoFactorRequirementEnabled
				}

				runners, _ := client.ListOrgRunners(ctx, org.Login)
				secrets, _ := client.ListOrgActionsSecrets(ctx, org.Login)
				repos, _ := client.ListOrgRepos(ctx, org.Login)
				repoCount := len(repos)
				if repoCount > 200 {
					repos = repos[:200]
				}

				checkLimit := 50
				if len(repos) < checkLimit {
					checkLimit = len(repos)
				}

				for j := 0; j < checkLimit; j++ {
					repo := repos[j]
					workflowFiles, err := client.GetWorkflowFiles(ctx, repo.Owner.Login, repo.Name)
					if err != nil {
						continue
					}

					for _, wf := range workflowFiles {
						content, err := client.GetWorkflowContent(ctx, repo.Owner.Login, repo.Name, wf.Path)
						if err != nil {
							continue
						}

						selfHostedJobs := extractSelfHostedJobs(content)
						if len(selfHostedJobs) > 0 {
							runnerLabels := make([]string, 0)
							for _, job := range selfHostedJobs {
								if labels, ok := job["labels"].([]string); ok {
									runnerLabels = append(runnerLabels, labels...)
								}
							}

							reposWithRunners = append(reposWithRunners, map[string]interface{}{
								"repo":           repo.FullName,
								"org":            org.Login,
								"visibility":     map[bool]string{true: "private", false: "public"}[repo.Private],
								"default_branch": repo.DefaultBranch,
								"runners":        runnerLabels,
								"workflow":       wf.Name,
							})
							break // Only need one workflow per repo
						}
					}
				}

				orgResults = append(orgResults, map[string]interface{}{
					"login":       org.Login,
					"description": org.Description,
					"admin":       isAdmin,
					"sso":         sso,
					"runners":     runners,
					"secrets":     secrets,
					"repos":       repoCount,
				})

				if i%5 == 0 {
					percent := 30 + (i * 60 / len(orgs))
					reportProgress(percent, fmt.Sprintf("Analyzed %d/%d organizations", i, len(orgs)))
				}
			}

			result := map[string]interface{}{
				"user": map[string]interface{}{
					"login": tokenInfo.User,
					"name":  tokenInfo.Name,
				},
				"scopes":             tokenInfo.Scopes,
				"orgs":               orgResults,
				"repos_with_runners": reposWithRunners,
			}

			resultJSON, err := json.Marshal(result)
			if err != nil {
				reject.Invoke(map[string]interface{}{"error": fmt.Sprintf("marshal failed: %v", err)})
				return
			}

			reportProgress(100, fmt.Sprintf("Enumeration complete - %d orgs, %d repos with runners", len(orgResults), len(reposWithRunners)))

			resolve.Invoke(map[string]interface{}{"result": string(resultJSON)})
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
				handleGitHubEnumerate(ctx, operation, options, resolve, reject)
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

// handleGitHubEnumerate routes GitHub enumerate operations
func handleGitHubEnumerate(ctx context.Context, operation string, options js.Value, resolve, reject js.Value) {
	token := options.Get("token").String()
	if token == "" {
		reject.Invoke(map[string]interface{}{"error": "token required"})
		return
	}

	target := ""
	if !options.Get("target").IsUndefined() {
		target = options.Get("target").String()
	}

	progressCallback := getProgressCallback(options)

	progressCallback(10, "Initializing GitHub client...")
	platform := github.NewPlatform()
	if err := platform.Init(ctx, platforms.Config{Token: token}); err != nil {
		reject.Invoke(map[string]interface{}{"error": fmt.Sprintf("failed to initialize platform: %v", err)})
		return
	}

	switch operation {
	case "repos", "repositories":
		enumerateGitHubRepos(ctx, platform, target, progressCallback, resolve, reject)
	case "secrets":
		enumerateGitHubSecrets(ctx, platform, target, progressCallback, resolve, reject)
	case "runners":
		enumerateGitHubRunners(ctx, platform, target, progressCallback, resolve, reject)
	default:
		reject.Invoke(map[string]interface{}{
			"error": fmt.Sprintf("unsupported GitHub operation: %s", operation),
		})
	}
}

func enumerateGitHubRepos(ctx context.Context, platform *github.Platform, target string, progressCallback ProgressCallback, resolve, reject js.Value) {
	progressCallback(20, "Enumerating repositories...")

	var targetType platforms.TargetType
	if target != "" {
		targetType = platforms.TargetOrg
	} else {
		targetType = platforms.TargetUser
	}

	result, err := platform.EnumerateRepos(ctx, platforms.Target{
		Type:  targetType,
		Value: target,
	})
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

func enumerateGitHubSecrets(ctx context.Context, platform *github.Platform, target string, progressCallback ProgressCallback, resolve, reject js.Value) {
	if target == "" {
		reject.Invoke(map[string]interface{}{"error": "target organization required for secrets enumeration"})
		return
	}

	progressCallback(20, "Enumerating secrets...")

	client := platform.Client()
	secrets, err := client.ListOrgActionsSecrets(ctx, target)
	if err != nil {
		reject.Invoke(map[string]interface{}{"error": err.Error()})
		return
	}

	progressCallback(100, "Complete")

	jsonBytes, err := json.Marshal(map[string]interface{}{
		"secrets": secrets,
		"count":   len(secrets),
	})
	if err != nil {
		reject.Invoke(map[string]interface{}{"error": fmt.Sprintf("failed to marshal results: %v", err)})
		return
	}

	resolve.Invoke(map[string]interface{}{
		"result": string(jsonBytes),
	})
}

func enumerateGitHubRunners(ctx context.Context, platform *github.Platform, target string, progressCallback ProgressCallback, resolve, reject js.Value) {
	if target == "" {
		reject.Invoke(map[string]interface{}{"error": "target organization required for runners enumeration"})
		return
	}

	progressCallback(20, "Enumerating runners...")

	client := platform.Client()
	runners, err := client.ListOrgRunners(ctx, target)
	if err != nil {
		reject.Invoke(map[string]interface{}{"error": err.Error()})
		return
	}

	progressCallback(100, "Complete")

	jsonBytes, err := json.Marshal(map[string]interface{}{
		"runners": runners,
		"count":   len(runners),
	})
	if err != nil {
		reject.Invoke(map[string]interface{}{"error": fmt.Sprintf("failed to marshal results: %v", err)})
		return
	}

	resolve.Invoke(map[string]interface{}{
		"result": string(jsonBytes),
	})
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
