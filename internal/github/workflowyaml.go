package github

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	yaml "go.yaml.in/yaml/v3"
)

// Lines are 1-based inclusive.
type LineNode struct {
	Value     any
	StartLine int
	EndLine   int
}

// ${{ ... }} expressions are substituted out before decode and restored on the walk,
// because a raw expression in flow context is not parseable YAML. Empty input returns
// (nil, nil).
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
	tree, err := convertNode(root, &aliasBudget{left: aliasExpansionFactor * countNodes(root)})
	if err != nil {
		return nil, err
	}
	if len(originals) > 0 {
		restoreInTree(tree, originals)
	}
	return tree, nil
}

// The library's aliasing guard fires only when decoding into any, not into yaml.Node.
const aliasExpansionFactor = 10

type aliasBudget struct{ left int }

func (b *aliasBudget) spend() error {
	b.left--
	if b.left < 0 {
		return fmt.Errorf("decode workflow yaml: document contains excessive aliasing")
	}
	return nil
}

func countNodes(node *yaml.Node) int {
	n := 1
	for _, c := range node.Content {
		n += countNodes(c)
	}
	return n
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

func convertNode(node *yaml.Node, budget *aliasBudget) (*LineNode, error) {
	if err := budget.spend(); err != nil {
		return nil, err
	}
	start := node.Line
	switch node.Kind {
	case yaml.MappingNode:
		mapping := make(map[string]*LineNode, len(node.Content)/2)
		end := start
		for i := 0; i+1 < len(node.Content); i += 2 {
			keyNode, valNode := node.Content[i], node.Content[i+1]
			key := scalarKey(keyNode)
			child, err := convertNode(valNode, budget)
			if err != nil {
				return nil, err
			}
			mapping[key] = child
			end = max(end, child.EndLine)
		}
		return &LineNode{Value: mapping, StartLine: start, EndLine: end}, nil
	case yaml.SequenceNode:
		items := make([]*LineNode, 0, len(node.Content))
		end := start
		for _, c := range node.Content {
			child, err := convertNode(c, budget)
			if err != nil {
				return nil, err
			}
			items = append(items, child)
			end = max(end, child.EndLine)
		}
		return &LineNode{Value: items, StartLine: start, EndLine: end}, nil
	case yaml.AliasNode:
		if node.Alias != nil {
			resolved, err := convertNode(node.Alias, budget)
			if err != nil {
				return nil, err
			}
			resolved.StartLine = start
			return resolved, nil
		}
		return &LineNode{Value: nil, StartLine: start, EndLine: start}, nil
	default:
		val := scalarValue(node)
		end := start
		if s, ok := val.(string); ok {
			end = start + strings.Count(s, "\n")
		}
		return &LineNode{Value: val, StartLine: start, EndLine: max(start, end)}, nil
	}
}

func scalarKey(keyNode *yaml.Node) string {
	if keyNode.Kind == yaml.ScalarNode {
		if s, ok := scalarValue(keyNode).(string); ok {
			return s
		}
	}
	key, err := convertNode(keyNode, &aliasBudget{left: aliasExpansionFactor * countNodes(keyNode)})
	if err != nil {
		return keyNode.Value
	}
	return fmt.Sprintf("%v", key.Plain())
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
			switch text[j : j+2] {
			case "{{":
				depth++
				j += 2
			case "}}":
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
