package detect

import "strings"

// A non-numeric segment against a list projects the remaining path across every
// element (steps.uses → the list of each element's uses) and returns immediately.
func getPath(subject any, path string) any {
	cur := subject
	parts := strings.Split(path, ".")
	for i := 0; i < len(parts); i++ {
		if cur == nil {
			return nil
		}
		part := parts[i]
		switch c := cur.(type) {
		case map[string]any:
			cur = c[part]
		case []any:
			if idx, ok := parseIndex(part); ok {
				if idx < 0 || idx >= len(c) {
					return nil
				}
				cur = c[idx]
				continue
			}
			remaining := parts[i:]
			projected := make([]any, 0, len(c))
			for _, item := range c {
				projected = append(projected, walkSegments(item, remaining))
			}
			return projected
		default:
			return nil
		}
	}
	return cur
}

func walkSegments(val any, segs []string) any {
	for _, seg := range segs {
		m, ok := val.(map[string]any)
		if !ok {
			return nil
		}
		val = m[seg]
	}
	return val
}

// Only pure digit runs are indices; any other token falls through to projection.
func parseIndex(s string) (int, bool) {
	if s == "" {
		return 0, false
	}
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, false
		}
		n = n*10 + int(r-'0')
	}
	return n, true
}
