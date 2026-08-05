package attack

import (
	"fmt"
	"strconv"
	"strings"
)

type patchHunk struct {
	oldStart int
	lines    []string // each retains its leading ' ', '-' or '+'
}

type patchFile struct {
	oldPath string // empty for a new file
	newPath string // empty for a deletion
	hunks   []patchHunk
}

// parsePatch reads a unified diff. It is deliberately strict: no fuzz, no
// offset search. A hunk that does not match its stated position is an authoring
// error the operator must see, not something to guess at on a live target.
func parsePatch(patch string) ([]patchFile, error) {
	var files []patchFile
	var cur *patchFile
	lines := strings.Split(strings.ReplaceAll(patch, "\r\n", "\n"), "\n")

	for i := 0; i < len(lines); i++ {
		line := lines[i]
		switch {
		case strings.HasPrefix(line, "--- "):
			files = append(files, patchFile{oldPath: diffPath(line[4:])})
			cur = &files[len(files)-1]
		case strings.HasPrefix(line, "+++ "):
			if cur == nil {
				return nil, fmt.Errorf("patch: +++ header with no matching ---")
			}
			cur.newPath = diffPath(line[4:])
		case strings.HasPrefix(line, "@@"):
			if cur == nil {
				return nil, fmt.Errorf("patch: hunk with no file header")
			}
			start, err := hunkStart(line)
			if err != nil {
				return nil, err
			}
			cur.hunks = append(cur.hunks, patchHunk{oldStart: start})
		case cur == nil || len(cur.hunks) == 0:
			continue // diff --git, index, mode lines and other preamble
		case line == "":
			// A blank final line is the trailing newline of the document, not a
			// context line; a blank context line inside a hunk is " ".
			if i == len(lines)-1 {
				continue
			}
			return nil, fmt.Errorf("patch: unprefixed line %d inside a hunk", i+1)
		case strings.HasPrefix(line, `\`):
			continue // "\ No newline at end of file"
		case line[0] == ' ' || line[0] == '-' || line[0] == '+':
			h := &cur.hunks[len(cur.hunks)-1]
			h.lines = append(h.lines, line)
		default:
			return nil, fmt.Errorf("patch: unexpected line %d: %q", i+1, line)
		}
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("patch: no file headers found")
	}
	return files, nil
}

func diffPath(s string) string {
	s = strings.TrimSpace(s)
	if s == "/dev/null" {
		return ""
	}
	if tab := strings.IndexByte(s, '\t'); tab >= 0 {
		s = s[:tab]
	}
	if p, ok := strings.CutPrefix(s, "a/"); ok {
		return p
	}
	if p, ok := strings.CutPrefix(s, "b/"); ok {
		return p
	}
	return s
}

func hunkStart(header string) (int, error) {
	_, rest, ok := strings.Cut(header, "-")
	if !ok {
		return 0, fmt.Errorf("patch: malformed hunk header %q", header)
	}
	span, _, _ := strings.Cut(rest, " ")
	count, _, _ := strings.Cut(span, ",")
	n, err := strconv.Atoi(count)
	if err != nil {
		return 0, fmt.Errorf("patch: malformed hunk header %q", header)
	}
	return n, nil
}

func applyHunks(path, src string, hunks []patchHunk) (string, error) {
	srcLines := splitLines(src)
	out := make([]string, 0, len(srcLines))
	cursor := 0

	for hi, h := range hunks {
		start := max(h.oldStart-1, 0)
		if start < cursor || start > len(srcLines) {
			return "", fmt.Errorf("patch %s hunk %d: starts at line %d, which is out of order or past the end of the file", path, hi+1, h.oldStart)
		}
		out = append(out, srcLines[cursor:start]...)
		cursor = start
		for _, l := range h.lines {
			text := l[1:]
			switch l[0] {
			case ' ', '-':
				if cursor >= len(srcLines) || srcLines[cursor] != text {
					return "", fmt.Errorf("patch %s hunk %d: context mismatch at line %d", path, hi+1, cursor+1)
				}
				if l[0] == ' ' {
					out = append(out, text)
				}
				cursor++
			case '+':
				out = append(out, text)
			}
		}
	}
	out = append(out, srcLines[cursor:]...)

	joined := strings.Join(out, "\n")
	if len(out) > 0 && (src == "" || strings.HasSuffix(src, "\n")) {
		joined += "\n"
	}
	return joined, nil
}

func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(strings.TrimSuffix(strings.ReplaceAll(s, "\r\n", "\n"), "\n"), "\n")
}
