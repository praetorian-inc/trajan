// Package report is the single consumer-facing renderer. It loads canonical
// findings off a run's 20-scan/ output, assigns run-local ids, filters by
// threshold, and serializes to json/jsonl/md/html. It operates only on the
// canonical record and never branches on provider.
package report

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/praetorian-inc/trajan/internal/engine"
	"github.com/praetorian-inc/trajan/internal/finding"
)

type Options struct {
	Format        string // json | jsonl | md | html | all
	MinSeverity   string // default info  (emit everything)
	MinConfidence string // default low   (emit everything)
	Out           string // "" = default (stdout for json/jsonl, file for md/html); "-" = stdout; else a directory
}

var validFormats = map[string]bool{"json": true, "jsonl": true, "md": true, "html": true, "all": true}

func Run(ctx context.Context, runDir string, opts Options) error {
	if !validFormats[opts.Format] {
		return fmt.Errorf("unknown format %q (want json|jsonl|md|html|all)", opts.Format)
	}
	if opts.Format == "all" && opts.Out == "-" {
		return fmt.Errorf("--format all writes three files and cannot go to stdout")
	}
	opts.MinSeverity = cmp.Or(opts.MinSeverity, "info")
	opts.MinConfidence = cmp.Or(opts.MinConfidence, "low")

	findings, err := load(runDir)
	if err != nil {
		return err
	}
	findings = filterAndOrder(findings, opts)

	state, _ := engine.LoadState(runDir) // best-effort header data; a missing _meta.json is not fatal
	meta := reportMeta{
		RunID:        filepath.Base(runDir),
		Org:          state.Org,
		GeneratedAt:  engine.IsoformatUTC(time.Now()),
		Total:        len(findings),
		BySeverity:   countBy(findings, func(f finding.Finding) string { return f.Severity }),
		ByConfidence: countBy(findings, func(f finding.Finding) string { return f.Confidence }),
	}

	switch opts.Format {
	case "jsonl":
		b, err := renderJSONL(findings)
		if err != nil {
			return err
		}
		return emit(runDir, opts, opts.Format, "findings.jsonl", b)
	case "json":
		b, err := renderJSON(findings)
		if err != nil {
			return err
		}
		return emit(runDir, opts, opts.Format, "findings.json", b)
	case "md":
		return emit(runDir, opts, opts.Format, "findings.md", renderMarkdown(meta, findings))
	case "html":
		return emit(runDir, opts, opts.Format, "findings.html", renderHTML(meta, findings))
	case "all":
		jsonl, err := renderJSONL(findings)
		if err != nil {
			return err
		}
		for _, w := range []struct {
			name string
			data []byte
		}{
			{"findings.html", renderHTML(meta, findings)},
			{"findings.jsonl", jsonl},
			{"findings.md", renderMarkdown(meta, findings)},
		} {
			if err := emit(runDir, opts, "all", w.name, w.data); err != nil {
				return err
			}
		}
	}
	return nil
}

func load(runDir string) ([]finding.Finding, error) {
	files, err := engine.PriorPhase{RunDir: runDir}.IterJSON(filepath.Join("20-scan", "findings"))
	if err != nil {
		return nil, fmt.Errorf("load findings: %w", err)
	}
	out := make([]finding.Finding, 0, len(files))
	for _, pf := range files {
		var f finding.Finding
		if err := json.Unmarshal(pf.Data, &f); err != nil {
			return nil, fmt.Errorf("bad finding %s: %w", pf.Rel, err)
		}
		out = append(out, f)
	}
	return out, nil
}

// filterAndOrder drops findings below either threshold, sorts the survivors
// (severity desc, then rule id, then subject id) and assigns contiguous F-NNN
// ids over what will actually be reported, so the report reads F-001..F-NNN and
// a re-render of the same run + thresholds is byte-stable.
func filterAndOrder(findings []finding.Finding, opts Options) []finding.Finding {
	minSev := finding.SeverityRank(opts.MinSeverity)
	minConf := finding.ConfidenceRank(opts.MinConfidence)

	kept := findings[:0]
	for _, f := range findings {
		if finding.SeverityRank(f.Severity) >= minSev && finding.ConfidenceRank(f.Confidence) >= minConf {
			kept = append(kept, f)
		}
	}

	slices.SortFunc(kept, func(a, b finding.Finding) int {
		if d := finding.SeverityRank(b.Severity) - finding.SeverityRank(a.Severity); d != 0 {
			return d
		}
		if d := cmp.Compare(ruleID(a), ruleID(b)); d != 0 {
			return d
		}
		return cmp.Compare(a.Subject.ID, b.Subject.ID)
	})

	for i := range kept {
		kept[i].FindingID = fmt.Sprintf("F-%03d", i+1)
	}
	return kept
}

func ruleID(f finding.Finding) string {
	if f.Rule == nil {
		return ""
	}
	return f.Rule.ID
}

func countBy(findings []finding.Finding, key func(finding.Finding) string) map[string]int {
	m := map[string]int{}
	for _, f := range findings {
		m[key(f)]++
	}
	return m
}

func renderJSONL(findings []finding.Finding) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	for _, f := range findings {
		if err := enc.Encode(f); err != nil { // Encode appends a newline → one object per line
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

func renderJSON(findings []finding.Finding) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(struct {
		Findings []finding.Finding `json:"findings"`
	}{findings}); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// emit sends data to stdout or a file. json/jsonl default to stdout (pipe to a
// platform); md/html/all default to a file in the run dir. Out=="-" forces
// stdout; a non-empty Out is treated as a destination directory.
func emit(runDir string, opts Options, format, filename string, data []byte) error {
	toStdout := opts.Out == "-" || (opts.Out == "" && (format == "json" || format == "jsonl"))
	if toStdout {
		_, err := os.Stdout.Write(data)
		return err
	}
	dir := cmp.Or(opts.Out, runDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(dir, filename)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return err
	}
	slog.Info("report written", "path", path)
	return nil
}
