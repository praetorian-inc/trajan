package engine

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// HTML escaping is disabled so '&', '<', '>' are emitted literally (Python's
// json.dumps does), matching byte-for-byte; these chars are pervasive in
// workflow data. No trailing newline and non-atomic overwrite also match Python.
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
