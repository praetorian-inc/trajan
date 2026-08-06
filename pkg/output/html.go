package output

import (
	"bytes"
	"fmt"
	"html/template"
	"sort"
	"strings"
	"time"

	"github.com/praetorian-inc/trajan/pkg/detections"
	"github.com/praetorian-inc/trajan/pkg/platforms"
)

type HTMLReportData struct {
	Title       string
	GeneratedAt string
	Version     string

	TotalFindings   int
	CriticalCount   int
	HighCount       int
	MediumCount     int
	LowCount        int
	InfoCount       int
	RepositoryCount int
	WorkflowCount   int

	FindingsByRepo  map[string][]detections.Finding
	RepositoryNames []string // Sorted.

	Findings []detections.Finding
}

func GenerateHTML(result *platforms.ScanResult, findings []detections.Finding) ([]byte, error) {
	data := buildHTMLReportData(result, findings)

	tmpl, err := template.New("html").Funcs(template.FuncMap{
		"severityClass":    severityClass,
		"severityColorHex": severityColorHex,
		"escapeHTML":       template.HTMLEscapeString,
		"mul":              func(a, b float64) float64 { return a * b },
		"div": func(a, b int) float64 {
			if b == 0 {
				return 0
			}
			return float64(a) / float64(b)
		},
		"add": func(a, b float64) float64 { return a + b },
	}).Parse(htmlTemplate)
	if err != nil {
		return nil, fmt.Errorf("parsing template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("executing template: %w", err)
	}

	return buf.Bytes(), nil
}

func buildHTMLReportData(result *platforms.ScanResult, findings []detections.Finding) *HTMLReportData {
	data := &HTMLReportData{
		Title:       "Trajan Security Report",
		GeneratedAt: time.Now().Format("2006-01-02 15:04:05 MST"),
		Version:     toolVersion,
		Findings:    findings,
	}

	data.RepositoryCount = len(result.Repositories)

	for _, workflows := range result.Workflows {
		data.WorkflowCount += len(workflows)
	}

	data.TotalFindings = len(findings)
	for _, f := range findings {
		switch f.Severity {
		case detections.SeverityCritical:
			data.CriticalCount++
		case detections.SeverityHigh:
			data.HighCount++
		case detections.SeverityMedium:
			data.MediumCount++
		case detections.SeverityLow:
			data.LowCount++
		case detections.SeverityInfo:
			data.InfoCount++
		}
	}

	data.FindingsByRepo = make(map[string][]detections.Finding)
	for _, f := range findings {
		data.FindingsByRepo[f.Repository] = append(data.FindingsByRepo[f.Repository], f)
	}

	data.RepositoryNames = make([]string, 0, len(data.FindingsByRepo))
	for repo := range data.FindingsByRepo {
		data.RepositoryNames = append(data.RepositoryNames, repo)
	}
	sort.Strings(data.RepositoryNames)

	return data
}

func severityClass(severity detections.Severity) string {
	return fmt.Sprintf("severity-%s", strings.ToLower(string(severity)))
}

func severityColorHex(severity detections.Severity) string {
	switch severity {
	case detections.SeverityCritical:
		return "#dc2626" // Red
	case detections.SeverityHigh:
		return "#ea580c" // Orange
	case detections.SeverityMedium:
		return "#f59e0b" // Yellow
	case detections.SeverityLow:
		return "#3b82f6" // Blue
	case detections.SeverityInfo:
		return "#6b7280" // Gray
	default:
		return "#6b7280"
	}
}

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ .Title }}</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background-color: #0f172a;
            color: #e2e8f0;
            line-height: 1.6;
            padding: 2rem;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            background-color: #1e293b;
            border-radius: 8px;
            padding: 2rem;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3);
        }

        header {
            border-bottom: 2px solid #334155;
            padding-bottom: 1.5rem;
            margin-bottom: 2rem;
        }

        h1 {
            color: #f1f5f9;
            font-size: 2rem;
            font-weight: 700;
            margin-bottom: 0.5rem;
        }

        .subtitle {
            color: #94a3b8;
            font-size: 0.875rem;
        }

        h2 {
            color: #f1f5f9;
            font-size: 1.5rem;
            font-weight: 600;
            margin-top: 2rem;
            margin-bottom: 1rem;
            border-bottom: 1px solid #334155;
            padding-bottom: 0.5rem;
        }

        h3 {
            color: #cbd5e1;
            font-size: 1.25rem;
            font-weight: 500;
            margin-top: 1.5rem;
            margin-bottom: 0.75rem;
        }

        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 1rem;
            margin: 2rem 0;
        }

        .summary-card {
            background-color: #334155;
            border-radius: 6px;
            padding: 1rem;
            text-align: center;
        }

        .summary-card .label {
            color: #94a3b8;
            font-size: 0.875rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        .summary-card .value {
            color: #f1f5f9;
            font-size: 2rem;
            font-weight: 700;
            margin-top: 0.5rem;
        }

        .severity-badge {
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        .severity-critical {
            background-color: #dc2626;
            color: #fff;
        }

        .severity-high {
            background-color: #ea580c;
            color: #fff;
        }

        .severity-medium {
            background-color: #f59e0b;
            color: #000;
        }

        .severity-low {
            background-color: #3b82f6;
            color: #fff;
        }

        .severity-info {
            background-color: #6b7280;
            color: #fff;
        }

        .chart-container {
            background-color: #334155;
            border-radius: 6px;
            padding: 1.5rem;
            margin: 2rem 0;
        }

        .findings-by-repo {
            margin-top: 2rem;
        }

        .repo-section {
            background-color: #334155;
            border-radius: 6px;
            padding: 1rem;
            margin-bottom: 1.5rem;
        }

        .repo-title {
            color: #f1f5f9;
            font-size: 1.125rem;
            font-weight: 600;
            margin-bottom: 1rem;
        }

        details {
            background-color: #475569;
            border-radius: 4px;
            padding: 0.75rem;
            margin-bottom: 0.75rem;
        }

        summary {
            cursor: pointer;
            font-weight: 500;
            color: #f1f5f9;
            user-select: none;
            list-style: none;
        }

        summary::-webkit-details-marker {
            display: none;
        }

        summary::before {
            content: "▶ ";
            display: inline-block;
            transition: transform 0.2s;
        }

        details[open] summary::before {
            transform: rotate(90deg);
        }

        .finding-details {
            margin-top: 0.75rem;
            padding-top: 0.75rem;
            border-top: 1px solid #64748b;
        }

        .finding-field {
            margin-bottom: 0.5rem;
        }

        .finding-field strong {
            color: #94a3b8;
            display: inline-block;
            min-width: 120px;
        }

        .finding-field span {
            color: #e2e8f0;
        }

        .evidence {
            background-color: #1e293b;
            border-left: 3px solid #3b82f6;
            padding: 0.75rem;
            margin: 0.75rem 0;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            font-size: 0.875rem;
            color: #cbd5e1;
            white-space: pre-wrap;
            word-break: break-word;
        }

        .remediation {
            background-color: #1e293b;
            border-left: 3px solid #10b981;
            padding: 0.75rem;
            margin: 0.75rem 0;
            border-radius: 4px;
            color: #cbd5e1;
        }

        .no-findings {
            text-align: center;
            padding: 3rem;
            color: #94a3b8;
            font-size: 1.125rem;
        }

        .no-findings .icon {
            font-size: 3rem;
            color: #10b981;
            margin-bottom: 1rem;
        }

        footer {
            margin-top: 3rem;
            padding-top: 1.5rem;
            border-top: 1px solid #334155;
            text-align: center;
            color: #64748b;
            font-size: 0.875rem;
        }

        @media print {
            body {
                background-color: #fff;
                color: #000;
            }

            .container {
                background-color: #fff;
                box-shadow: none;
            }

            details {
                border: 1px solid #ccc;
            }

            details[open] {
                page-break-inside: avoid;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>{{ .Title }}</h1>
            <p class="subtitle">Generated: {{ .GeneratedAt }} | Version: {{ .Version }}</p>
        </header>

        <section class="executive-summary">
            <h2>Executive Summary</h2>
            <div class="summary-grid">
                <div class="summary-card">
                    <div class="label">Total Findings</div>
                    <div class="value">{{ .TotalFindings }}</div>
                </div>
                <div class="summary-card">
                    <div class="label">Repositories</div>
                    <div class="value">{{ .RepositoryCount }}</div>
                </div>
                <div class="summary-card">
                    <div class="label">Workflows</div>
                    <div class="value">{{ .WorkflowCount }}</div>
                </div>
            </div>

            <h3>Severity Breakdown</h3>
            <div class="summary-grid">
                <div class="summary-card">
                    <div class="label">Critical</div>
                    <div class="value" style="color: #dc2626;">{{ .CriticalCount }}</div>
                </div>
                <div class="summary-card">
                    <div class="label">High</div>
                    <div class="value" style="color: #ea580c;">{{ .HighCount }}</div>
                </div>
                <div class="summary-card">
                    <div class="label">Medium</div>
                    <div class="value" style="color: #f59e0b;">{{ .MediumCount }}</div>
                </div>
                <div class="summary-card">
                    <div class="label">Low</div>
                    <div class="value" style="color: #3b82f6;">{{ .LowCount }}</div>
                </div>
                <div class="summary-card">
                    <div class="label">Info</div>
                    <div class="value" style="color: #6b7280;">{{ .InfoCount }}</div>
                </div>
            </div>
        </section>

        <section class="severity-chart">
            <h2>Severity Distribution</h2>
            <div class="chart-container">
                <svg width="100%" height="200" viewBox="0 0 600 200" xmlns="http://www.w3.org/2000/svg">
                    {{ if eq .TotalFindings 0 }}
                    <text x="300" y="100" text-anchor="middle" fill="#94a3b8" font-size="16">No vulnerabilities found</text>
                    {{ else }}
                    <!-- Critical -->
                    {{ if gt .CriticalCount 0 }}
                    <rect x="0" y="0" width="100" height="100" fill="#dc2626"/>
                    <text x="50" y="50" text-anchor="middle" fill="#fff" font-size="14" font-weight="bold">{{ .CriticalCount }}</text>
                    <text x="50" y="65" text-anchor="middle" fill="#fff" font-size="10">Critical</text>
                    {{ end }}
                    <!-- High -->
                    {{ if gt .HighCount 0 }}
                    <rect x="120" y="0" width="100" height="100" fill="#ea580c"/>
                    <text x="170" y="50" text-anchor="middle" fill="#fff" font-size="14" font-weight="bold">{{ .HighCount }}</text>
                    <text x="170" y="65" text-anchor="middle" fill="#fff" font-size="10">High</text>
                    {{ end }}
                    <!-- Medium -->
                    {{ if gt .MediumCount 0 }}
                    <rect x="240" y="0" width="100" height="100" fill="#f59e0b"/>
                    <text x="290" y="50" text-anchor="middle" fill="#000" font-size="14" font-weight="bold">{{ .MediumCount }}</text>
                    <text x="290" y="65" text-anchor="middle" fill="#000" font-size="10">Medium</text>
                    {{ end }}
                    <!-- Low -->
                    {{ if gt .LowCount 0 }}
                    <rect x="360" y="0" width="100" height="100" fill="#3b82f6"/>
                    <text x="410" y="50" text-anchor="middle" fill="#fff" font-size="14" font-weight="bold">{{ .LowCount }}</text>
                    <text x="410" y="65" text-anchor="middle" fill="#fff" font-size="10">Low</text>
                    {{ end }}
                    <!-- Info -->
                    {{ if gt .InfoCount 0 }}
                    <rect x="480" y="0" width="100" height="100" fill="#6b7280"/>
                    <text x="530" y="50" text-anchor="middle" fill="#fff" font-size="14" font-weight="bold">{{ .InfoCount }}</text>
                    <text x="530" y="65" text-anchor="middle" fill="#fff" font-size="10">Info</text>
                    {{ end }}
                    {{ end }}
                </svg>
            </div>
        </section>

        {{ if gt .TotalFindings 0 }}
        <section class="findings-by-repo">
            <h2>Findings by Repository</h2>
            {{ range .RepositoryNames }}
                {{ $repo := . }}
                {{ $findings := index $.FindingsByRepo $repo }}
                <div class="repo-section">
                    <div class="repo-title">{{ $repo }} ({{ len $findings }} findings)</div>
                    {{ range $findings }}
                    <details>
                        <summary>
                            <span class="severity-badge {{ severityClass .Severity }}">{{ .Severity }}</span>
                            {{ .Type }} - {{ .Workflow }}
                        </summary>
                        <div class="finding-details">
                            <div class="finding-field">
                                <strong>Platform:</strong>
                                <span>{{ .Platform }}</span>
                            </div>
                            <div class="finding-field">
                                <strong>Workflow:</strong>
                                <span>{{ .Workflow }}</span>
                            </div>
                            {{ if .Job }}
                            <div class="finding-field">
                                <strong>Job:</strong>
                                <span>{{ .Job }}</span>
                            </div>
                            {{ end }}
                            {{ if .Step }}
                            <div class="finding-field">
                                <strong>Step:</strong>
                                <span>{{ .Step }}</span>
                            </div>
                            {{ end }}
                            {{ if gt .Line 0 }}
                            <div class="finding-field">
                                <strong>Line:</strong>
                                <span>{{ .Line }}</span>
                            </div>
                            {{ end }}
                            <div class="finding-field">
                                <strong>Confidence:</strong>
                                <span>{{ .Confidence }}</span>
                            </div>
                            {{ if .Evidence }}
                            <div class="finding-field">
                                <strong>Evidence:</strong>
                            </div>
                            <div class="evidence">{{ .Evidence }}</div>
                            {{ end }}
                            {{ if .Remediation }}
                            <div class="finding-field">
                                <strong>Remediation:</strong>
                            </div>
                            <div class="remediation">{{ .Remediation }}</div>
                            {{ end }}
                        </div>
                    </details>
                    {{ end }}
                </div>
            {{ end }}
        </section>
        {{ else }}
        <section class="no-findings">
            <div class="icon">✓</div>
            <div>No vulnerabilities found</div>
        </section>
        {{ end }}

        <footer>
            <p>Generated by Trajan CI/CD Security Scanner {{ .Version }}</p>
            <p>{{ .GeneratedAt }}</p>
        </footer>
    </div>
</body>
</html>
`
