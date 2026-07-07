package github

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	yaml "go.yaml.in/yaml/v4"
)

// Lines are 1-based inclusive.
type LineNode struct {
	Value     any
	StartLine int
	EndLine   int
}

// DecodeWorkflow substitutes ${{ ... }} expressions out before decode and
// restores them on the walk, because a raw expression in flow context is not
// parseable YAML. Empty input returns (nil, nil).
func DecodeWorkflow(text string) (*LineNode, error) {
	preprocessed, originals := substituteExpressions(text)
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(preprocessed), &doc); err != nil {
		return nil, fmt.Errorf("decode workflow yaml: %w", err)
	}
	root := documentRoot(&doc)
	if root == nil {
		return nil, nil
	}
	tree := convertNode(root)
	if len(originals) > 0 {
		restoreInTree(tree, originals)
	}
	return tree, nil
}

func (n *LineNode) Field(key string) *LineNode {
	if n == nil {
		return nil
	}
	m, ok := n.Value.(map[string]*LineNode)
	if !ok {
		return nil
	}
	return m[key]
}

func (n *LineNode) FieldValue(key string, def any) any {
	child := n.Field(key)
	if child == nil {
		return def
	}
	return child.Plain()
}

func (n *LineNode) Plain() any {
	if n == nil {
		return nil
	}
	switch v := n.Value.(type) {
	case map[string]*LineNode:
		out := make(map[string]any, len(v))
		for k, child := range v {
			out[k] = child.Plain()
		}
		return out
	case []*LineNode:
		out := make([]any, len(v))
		for i, child := range v {
			out[i] = child.Plain()
		}
		return out
	default:
		return n.Value
	}
}

func (n *LineNode) Range() *LineRange {
	if n == nil {
		return nil
	}
	return &LineRange{n.StartLine, n.EndLine}
}

func documentRoot(doc *yaml.Node) *yaml.Node {
	if doc.Kind == yaml.DocumentNode {
		if len(doc.Content) == 0 {
			return nil
		}
		return doc.Content[0]
	}
	if doc.IsZero() {
		return nil
	}
	return doc
}

func convertNode(node *yaml.Node) *LineNode {
	start := node.Line
	switch node.Kind {
	case yaml.MappingNode:
		mapping := make(map[string]*LineNode, len(node.Content)/2)
		end := start
		for i := 0; i+1 < len(node.Content); i += 2 {
			keyNode, valNode := node.Content[i], node.Content[i+1]
			key := scalarKey(keyNode)
			child := convertNode(valNode)
			mapping[key] = child
			end = max(end, child.EndLine)
		}
		return &LineNode{Value: mapping, StartLine: start, EndLine: end}
	case yaml.SequenceNode:
		items := make([]*LineNode, 0, len(node.Content))
		end := start
		for _, c := range node.Content {
			child := convertNode(c)
			items = append(items, child)
			end = max(end, child.EndLine)
		}
		return &LineNode{Value: items, StartLine: start, EndLine: end}
	case yaml.AliasNode:
		if node.Alias != nil {
			resolved := convertNode(node.Alias)
			resolved.StartLine = start
			return resolved
		}
		return &LineNode{Value: nil, StartLine: start, EndLine: start}
	default:
		val := scalarValue(node)
		end := start
		if s, ok := val.(string); ok {
			end = start + strings.Count(s, "\n")
		}
		return &LineNode{Value: val, StartLine: start, EndLine: max(start, end)}
	}
}

func scalarKey(keyNode *yaml.Node) string {
	if keyNode.Kind == yaml.ScalarNode {
		if s, ok := scalarValue(keyNode).(string); ok {
			return s
		}
	}
	return fmt.Sprintf("%v", convertNode(keyNode).Plain())
}

// Timestamps keep their raw textual form rather than leaking time.Time.
func scalarValue(node *yaml.Node) any {
	var v any
	if err := node.Decode(&v); err != nil {
		return node.Value
	}
	switch t := v.(type) {
	case int:
		return int64(t)
	case int64:
		return t
	case uint64:
		if t <= 1<<63-1 {
			return int64(t)
		}
		return node.Value
	case time.Time:
		return node.Value
	case nil, bool, float64, string:
		return v
	default:
		if i, err := strconv.ParseInt(node.Value, 10, 64); err == nil {
			return i
		}
		return node.Value
	}
}

const exprPlaceholderPrefix = "GHEXPRZZ"

// Brace depth is tracked so literal-brace escapes ({{ / }}) inside an expression
// body do not terminate it early. An unterminated ${{ ends the scan.
func findExpressionSpans(text string) [][2]int {
	var spans [][2]int
	n := len(text)
	for i := 0; i < n-2; {
		if text[i:i+3] != "${{" {
			i++
			continue
		}
		start := i
		depth := 1
		j := i + 3
		closed := false
		for j < n-1 {
			switch {
			case text[j:j+2] == "{{":
				depth++
				j += 2
			case text[j:j+2] == "}}":
				depth--
				j += 2
				if depth == 0 {
					spans = append(spans, [2]int{start, j})
					i = j
					closed = true
				}
			default:
				j++
			}
			if closed {
				break
			}
		}
		if !closed {
			break
		}
	}
	return spans
}

func substituteExpressions(text string) (string, []string) {
	spans := findExpressionSpans(text)
	if len(spans) == 0 {
		return text, nil
	}
	var originals []string
	var b strings.Builder
	cursor := 0
	for _, span := range spans {
		s, e := span[0], span[1]
		b.WriteString(text[cursor:s])
		original := text[s:e]
		idx := len(originals)
		originals = append(originals, original)
		b.WriteString(exprPlaceholderPrefix + strconv.Itoa(idx) + "@@")
		b.WriteString(strings.Repeat("\n", strings.Count(original, "\n")))
		cursor = e
	}
	b.WriteString(text[cursor:])
	return b.String(), originals
}

func restoreInTree(node *LineNode, originals []string) {
	if node == nil {
		return
	}
	switch v := node.Value.(type) {
	case string:
		node.Value = restoreInString(v, originals)
	case map[string]*LineNode:
		for _, child := range v {
			restoreInTree(child, originals)
		}
	case []*LineNode:
		for _, child := range v {
			restoreInTree(child, originals)
		}
	}
}

func restoreInString(s string, originals []string) string {
	if !strings.Contains(s, exprPlaceholderPrefix) {
		return s
	}
	var b strings.Builder
	i := 0
	for i < len(s) {
		if !strings.HasPrefix(s[i:], exprPlaceholderPrefix) {
			b.WriteByte(s[i])
			i++
			continue
		}
		j := i + len(exprPlaceholderPrefix)
		digits := j
		for digits < len(s) && s[digits] >= '0' && s[digits] <= '9' {
			digits++
		}
		if digits > j && strings.HasPrefix(s[digits:], "@@") {
			idx, _ := strconv.Atoi(s[j:digits])
			if idx >= 0 && idx < len(originals) {
				b.WriteString(originals[idx])
				i = digits + 2
				continue
			}
		}
		b.WriteString(s[i:j])
		i = j
	}
	return b.String()
}
