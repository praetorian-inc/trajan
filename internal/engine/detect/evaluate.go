package detect

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

type operator struct {
	symbol string
	op     string
}

// Order is precedence at each scan position (first match wins): >=/<= must
// precede >/< so the two-char forms win.
var operators = []operator{
	{"==", "eq"},
	{"!=", "ne"},
	{">=", "ge"},
	{"<=", "le"},
	{">", "gt"},
	{"<", "lt"},
	{"∋", "contains"},
	{"⊆", "subset"},
	{" matches ", "matches"},
	{" contains ", "contains"},
	{" subset_of ", "subset"},
	{" in ", "in"},
}

// Empty all_of → true, empty any_of → false, empty none_of → true; present keys
// are conjoined.
func evaluateBlock(block *Block, subject any) (bool, error) {
	if block == nil {
		return true, nil
	}
	if !block.IsCombo {
		return evaluatePredicate(block.Predicate, subject)
	}
	if block.AllOf == nil && block.AnyOf == nil && block.NoneOf == nil {
		return false, fmt.Errorf("block has no all_of/any_of/none_of")
	}
	result := true
	if block.AllOf != nil {
		for i := range block.AllOf {
			ok, err := evaluateBlock(&block.AllOf[i], subject)
			if err != nil {
				return false, err
			}
			if !ok {
				result = false
				break
			}
		}
	}
	if result && block.AnyOf != nil {
		any := false
		for i := range block.AnyOf {
			ok, err := evaluateBlock(&block.AnyOf[i], subject)
			if err != nil {
				return false, err
			}
			if ok {
				any = true
				break
			}
		}
		result = result && any
	}
	if result && block.NoneOf != nil {
		none := true
		for i := range block.NoneOf {
			ok, err := evaluateBlock(&block.NoneOf[i], subject)
			if err != nil {
				return false, err
			}
			if ok {
				none = false
				break
			}
		}
		result = result && none
	}
	return result, nil
}

func evaluatePredicate(predicate string, subject any) (bool, error) {
	field, op, rhs, ok := splitPredicate(predicate)
	if !ok {
		return false, fmt.Errorf("unparseable predicate: %q", predicate)
	}
	actual := getPath(subject, field)
	expected := parseValue(rhs)

	switch op {
	case "eq":
		return valuesEqual(actual, expected), nil
	case "ne":
		return !valuesEqual(actual, expected), nil
	case "contains":
		set := asSet(expected)
		if items, isList := asList(actual); isList {
			for _, item := range items {
				if setHas(set, item) {
					return true, nil
				}
			}
			return false, nil
		}
		return setHas(set, actual), nil
	case "subset":
		set := asSet(expected)
		items, isList := asList(actual)
		if !isList {
			return false, nil
		}
		for _, item := range items {
			if !setHas(set, item) {
				return false, nil
			}
		}
		return true, nil
	case "ge", "le", "gt", "lt":
		if actual == nil || expected == nil {
			return false, nil
		}
		a, aok := toFloat(actual)
		e, eok := toFloat(expected)
		if !aok || !eok {
			return false, nil
		}
		switch op {
		case "ge":
			return a >= e, nil
		case "le":
			return a <= e, nil
		case "gt":
			return a > e, nil
		default:
			return a < e, nil
		}
	case "matches":
		if actual == nil {
			return false, nil
		}
		pattern := toStringValue(expected)
		re, err := regexp.Compile(pattern)
		if err != nil {
			return false, nil
		}
		if items, isList := asList(actual); isList {
			for _, item := range items {
				if re.MatchString(toStringValue(item)) {
					return true, nil
				}
			}
			return false, nil
		}
		return re.MatchString(toStringValue(actual)), nil
	case "in":
		set := asSet(expected)
		return setHas(set, actual), nil
	default:
		return false, fmt.Errorf("unknown op: %s", op)
	}
}

// Advances by rune so the multi-byte glyphs (∋/⊆) stay aligned to a real
// position; an operator is detected by byte-prefix on the substring at i.
func splitPredicate(predicate string) (field, op, rhs string, ok bool) {
	var quote byte
	for i := 0; i < len(predicate); {
		ch := predicate[i]
		if quote != 0 {
			if ch == '\\' && i+1 < len(predicate) {
				i += 2
				continue
			}
			if ch == quote {
				quote = 0
			}
			i++
			continue
		}
		if ch == '\'' || ch == '"' {
			quote = ch
			i++
			continue
		}
		for _, entry := range operators {
			if strings.HasPrefix(predicate[i:], entry.symbol) {
				left := strings.TrimSpace(predicate[:i])
				if left != "" {
					right := strings.TrimSpace(predicate[i+len(entry.symbol):])
					return left, entry.op, right, true
				}
			}
		}
		i += sizeOfRuneAt(predicate, i)
	}
	return "", "", "", false
}

func sizeOfRuneAt(s string, i int) int {
	c := s[i]
	switch {
	case c < 0x80:
		return 1
	case c < 0xE0:
		return 2
	case c < 0xF0:
		return 3
	default:
		return 4
	}
}

func parseValue(text string) any {
	text = strings.TrimSpace(text)
	switch text {
	case "null", "None":
		return nil
	case "true":
		return true
	case "false":
		return false
	case "[]":
		return []any{}
	case "{}":
		return map[string]any{}
	}
	if len(text) >= 2 {
		if (text[0] == '"' && text[len(text)-1] == '"') ||
			(text[0] == '\'' && text[len(text)-1] == '\'') {
			return text[1 : len(text)-1]
		}
	}
	if len(text) >= 2 && text[0] == '{' && text[len(text)-1] == '}' {
		inner := text[1 : len(text)-1]
		set := map[string]struct{}{}
		for _, part := range strings.Split(inner, ",") {
			item := strings.TrimSpace(part)
			if item == "" {
				continue
			}
			item = strings.Trim(item, "'\"")
			set[item] = struct{}{}
		}
		return set
	}
	if n, err := strconv.Atoi(text); err == nil {
		return n
	}
	return text
}

// A scalar becomes a one-element set, mirroring Python wrapping it as {expected}.
func asSet(expected any) map[string]struct{} {
	if s, ok := expected.(map[string]struct{}); ok {
		return s
	}
	return map[string]struct{}{toSetKey(expected): {}}
}

func setHas(set map[string]struct{}, item any) bool {
	_, ok := set[toSetKey(item)]
	return ok
}

// Set members are always strings, so non-strings compare by their literal form.
func toSetKey(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", v)
}

func asList(v any) ([]any, bool) {
	l, ok := v.([]any)
	return l, ok
}

// JSON numbers decode to float64 but rhs integers parse to int, so numeric
// equality is compared in float space.
func valuesEqual(actual, expected any) bool {
	if actual == nil || expected == nil {
		return actual == nil && expected == nil
	}
	if a, aok := toFloat(actual); aok {
		if e, eok := toFloat(expected); eok {
			return a == e
		}
		return false
	}
	switch e := expected.(type) {
	case string:
		s, ok := actual.(string)
		return ok && s == e
	case bool:
		b, ok := actual.(bool)
		return ok && b == e
	case []any:
		l, ok := actual.([]any)
		return ok && len(l) == 0 && len(e) == 0
	case map[string]any:
		m, ok := actual.(map[string]any)
		return ok && len(m) == 0 && len(e) == 0
	}
	return false
}

// Bools are deliberately NOT coerced: keeping them out stops eq from treating
// true as 1.0.
func toFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(n), 64)
		if err != nil {
			return 0, false
		}
		return f, true
	default:
		return 0, false
	}
}

// Mirrors Python str(): bools render as True/False, nil as None.
func toStringValue(v any) string {
	switch s := v.(type) {
	case string:
		return s
	case float64:
		return strconv.FormatFloat(s, 'g', -1, 64)
	case bool:
		if s {
			return "True"
		}
		return "False"
	case nil:
		return "None"
	default:
		return fmt.Sprintf("%v", v)
	}
}
