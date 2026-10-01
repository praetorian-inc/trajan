package engine

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/praetorian-inc/trajan/pkg/finding"
)

// HTML escaping is off so '&', '<', '>' — pervasive in workflow data — are emitted
// literally, matching Python's json.dumps byte for byte; the trimmed trailing
// newline and non-atomic overwrite match it too.
func WriteJSON(absPath string, v any) error {
	if err := os.MkdirAll(filepath.Dir(absPath), 0o755); err != nil {
		return err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return err
	}
	b := bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
	return os.WriteFile(absPath, b, 0o644)
}

func ReadJSON(absPath string, v any) error {
	b, err := os.ReadFile(absPath)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

func WriteRaw(absPath string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(absPath), 0o755); err != nil {
		return err
	}
	return os.WriteFile(absPath, b, 0o644)
}

type PhaseFile struct {
	Rel  string
	Data []byte
}

type PriorPhase struct{ RunDir string }

func (p PriorPhase) Abs(rel string) string { return filepath.Join(p.RunDir, rel) }

// Files whose basename starts with "_" are skipped so _summary.json / _meta.json
// stay invisible to consumers. A missing phase directory yields an empty slice.
func (p PriorPhase) IterJSON(phaseDir string) ([]PhaseFile, error) {
	root := filepath.Join(p.RunDir, phaseDir)
	if _, err := os.Stat(root); os.IsNotExist(err) {
		return nil, nil
	}

	var paths []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		name := d.Name()
		if strings.HasPrefix(name, "_") {
			return nil
		}
		if !strings.HasSuffix(name, ".json") {
			return nil
		}
		paths = append(paths, path)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(paths)

	out := make([]PhaseFile, 0, len(paths))
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return nil, err
		}
		out = append(out, PhaseFile{Rel: rel, Data: data})
	}
	return out, nil
}

type CurrentPhase struct{ RunDir string }

func (c CurrentPhase) Write(rel string, v any) error {
	return WriteJSON(filepath.Join(c.RunDir, rel), v)
}

func (c CurrentPhase) WriteRaw(rel string, b []byte) error {
	return WriteRaw(filepath.Join(c.RunDir, rel), b)
}

func LoadFindings(ctx context.Context, cfg *Config, runDir string, onError func(error)) ([]finding.Finding, int, error) {
	pp := PriorPhase{RunDir: runDir}
	if _, err := os.Stat(pp.Abs(dirScan)); err != nil {
		return nil, 0, fmt.Errorf("%s unreadable; run the scan phase first: %w", dirScan, err)
	}
	files, err := pp.IterJSON(dirScan)
	if err != nil {
		return nil, 0, err
	}
	out, err := RunPartial(ctx, cfg.Concurrency, files,
		func(_ context.Context, f PhaseFile) (finding.Finding, error) {
			var v finding.Finding
			if err := json.Unmarshal(f.Data, &v); err != nil {
				return v, fmt.Errorf("%s/%s: %w", dirScan, f.Rel, err)
			}
			return v, nil
		},
		func(_ PhaseFile, err error) { onError(err) })
	if err != nil {
		return nil, 0, err
	}
	slices.SortFunc(out, func(a, b finding.Finding) int {
		return cmp.Or(cmp.Compare(findingRuleID(&a), findingRuleID(&b)), cmp.Compare(a.Fingerprint, b.Fingerprint))
	})
	return out, len(files), nil
}

func findingRuleID(f *finding.Finding) string {
	if f.Rule == nil {
		return ""
	}
	return f.Rule.ID
}
