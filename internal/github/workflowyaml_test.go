package github

import (
	"strings"
	"testing"
)

func walkTo(t *testing.T, n *LineNode, path ...any) *LineNode {
	t.Helper()
	cur := n
	for i, seg := range path {
		if cur == nil {
			t.Fatalf("walkTo: nil node before segment %d (%v)", i, seg)
		}
		switch key := seg.(type) {
		case string:
			m, ok := cur.Value.(map[string]*LineNode)
			if !ok {
				t.Fatalf("walkTo: segment %d expected map for key %q, got %T", i, key, cur.Value)
			}
			child, ok := m[key]
			if !ok {
				t.Fatalf("walkTo: key %q absent (have %v)", key, mapKeys(m))
			}
			cur = child
		case int:
			s, ok := cur.Value.([]*LineNode)
			if !ok {
				t.Fatalf("walkTo: segment %d expected seq for index %d, got %T", i, key, cur.Value)
			}
			if key < 0 || key >= len(s) {
				t.Fatalf("walkTo: index %d out of range (len %d)", key, len(s))
			}
			cur = s[key]
		default:
			t.Fatalf("walkTo: bad path segment type %T", seg)
		}
	}
	return cur
}

func mapKeys(m map[string]*LineNode) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func wantRange(t *testing.T, n *LineNode, start, end int) {
	t.Helper()
	if n.StartLine != start || n.EndLine != end {
		t.Fatalf("range = [%d-%d], want [%d-%d]", n.StartLine, n.EndLine, start, end)
	}
}

func wantString(t *testing.T, n *LineNode, want string) {
	t.Helper()
	got, ok := n.Value.(string)
	if !ok {
		t.Fatalf("value type = %T, want string", n.Value)
	}
	if got != want {
		t.Fatalf("value = %q, want %q", got, want)
	}
}

// A raw flow mapping with an unquoted ${{ makes the YAML parser fail outright,
// so the scalar must come back byte-identical via substitute/restore.
func TestDecodeWorkflow_InlineFlowMappingExpression(t *testing.T) {
	src := "jobs:\n" + // L1
		"  build:\n" + // L2
		"    steps:\n" + // L3
		"      - uses: actions/checkout@v4\n" + // L4
		"        with: { ref: ${{ github.event.pull_request.head.sha }} }\n" // L5

	tree, err := DecodeWorkflow(src)
	if err != nil {
		t.Fatalf("DecodeWorkflow returned error on inline-flow expression: %v", err)
	}
	if tree == nil {
		t.Fatal("tree is nil; flow mapping was silently dropped")
	}

	ref := walkTo(t, tree, "jobs", "build", "steps", 0, "with", "ref")
	wantString(t, ref, "${{ github.event.pull_request.head.sha }}")
	wantRange(t, ref, 5, 5)

	uses := walkTo(t, tree, "jobs", "build", "steps", 0, "uses")
	wantString(t, uses, "actions/checkout@v4")
}

func TestDecodeWorkflow_RawInlineFlowExpressionWouldFail(t *testing.T) {
	raw := "with: { ref: ${{ github.event.pull_request.head.sha }} }\n"
	if _, err := DecodeWorkflow(raw); err != nil {
		t.Fatalf("DecodeWorkflow should handle raw flow expression, got: %v", err)
	}
	pre, originals := substituteExpressions(raw)
	if strings.Contains(pre, "${{") {
		t.Fatalf("preprocessed text still contains a raw expression: %q", pre)
	}
	if len(originals) != 1 || originals[0] != "${{ github.event.pull_request.head.sha }}" {
		t.Fatalf("originals = %q, want one verbatim expression", originals)
	}
}

// A multiline ${{ }} must preserve its internal newline count, or the following
// step's run reports a wrong source line (provenance drift).
func TestDecodeWorkflow_MultilineExpressionPreservesLineNumbers(t *testing.T) {
	src := "jobs:\n" + // L1
		"  build:\n" + // L2
		"    steps:\n" + // L3
		"      - name: gate\n" + // L4
		"        if: >\n" + // L5
		"          ${{ github.actor == 'x'\n" + // L6
		"              && true }}\n" + // L7
		"        run: echo afterwards\n" // L8

	tree, err := DecodeWorkflow(src)
	if err != nil {
		t.Fatalf("DecodeWorkflow error: %v", err)
	}

	ifNode := walkTo(t, tree, "jobs", "build", "steps", 0, "if")
	wantString(t, ifNode, "${{ github.actor == 'x'\n              && true }}\n")
	wantRange(t, ifNode, 5, 6)

	// A collapsed newline would pull this up to line 7.
	runNode := walkTo(t, tree, "jobs", "build", "steps", 0, "run")
	wantString(t, runNode, "echo afterwards")
	wantRange(t, runNode, 8, 8)
}

// The `on:` key must survive as the string "on", not coerced to a boolean as
// PyYAML does — rules key on the string.
func TestDecodeWorkflow_PlainBlockStyle(t *testing.T) {
	src := "name: CI\n" + // L1
		"on:\n" + // L2
		"  push:\n" + // L3
		"    branches: [main]\n" + // L4
		"jobs:\n" + // L5
		"  build:\n" + // L6
		"    runs-on: ubuntu-latest\n" + // L7
		"    steps:\n" + // L8
		"      - name: checkout\n" + // L9
		"        uses: actions/checkout@v4\n" + // L10
		"      - name: build\n" + // L11
		"        run: |\n" + // L12
		"          echo one\n" + // L13
		"          echo two\n" + // L14
		"          make\n" // L15

	tree, err := DecodeWorkflow(src)
	if err != nil {
		t.Fatalf("DecodeWorkflow error: %v", err)
	}

	if tree.Field("on") == nil {
		t.Fatal(`"on" key missing; block-style on: not keyed as the string "on"`)
	}
	if tree.Field("name") == nil || tree.Field("jobs") == nil {
		t.Fatal("expected name and jobs keys")
	}

	// EndLine must cover the whole block-literal body, not just the `run:` line,
	// so a finding cites the whole script.
	runNode := walkTo(t, tree, "jobs", "build", "steps", 1, "run")
	wantString(t, runNode, "echo one\necho two\nmake\n")
	wantRange(t, runNode, 12, 15)

	runsOn := walkTo(t, tree, "jobs", "build", "runs-on")
	wantRange(t, runsOn, 7, 7)

	step0 := walkTo(t, tree, "jobs", "build", "steps", 0)
	wantRange(t, step0, 9, 10)
}

// Each expression must restore to its own original by index; a single-placeholder
// scheme would cross-wire them.
func TestDecodeWorkflow_MultipleExpressionsInOneScalar(t *testing.T) {
	src := "env:\n" +
		"  COMBINED: \"a-${{ github.head_ref }}-b-${{ github.sha }}-c\"\n"

	tree, err := DecodeWorkflow(src)
	if err != nil {
		t.Fatalf("DecodeWorkflow error: %v", err)
	}
	combined := walkTo(t, tree, "env", "COMBINED")
	wantString(t, combined, "a-${{ github.head_ref }}-b-${{ github.sha }}-c")
}

// `if: ${{ true }}` is an expression, not a YAML boolean — it must stay a string
// so the gate classifier sees the literal text.
func TestDecodeWorkflow_ExpressionScalarNotCoerced(t *testing.T) {
	src := "if_bool: ${{ true }}\n" +
		"if_num: ${{ 123 }}\n"

	tree, err := DecodeWorkflow(src)
	if err != nil {
		t.Fatalf("DecodeWorkflow error: %v", err)
	}
	wantString(t, walkTo(t, tree, "if_bool"), "${{ true }}")
	wantString(t, walkTo(t, tree, "if_num"), "${{ 123 }}")
}

// The inner }} in ${{ format('{{0}}', x) }} must not terminate the span early.
func TestDecodeWorkflow_LiteralBraceEscapeExpression(t *testing.T) {
	src := "name: ${{ format('{{0}}', x) }}\non: push\n"

	tree, err := DecodeWorkflow(src)
	if err != nil {
		t.Fatalf("DecodeWorkflow error: %v", err)
	}
	wantString(t, walkTo(t, tree, "name"), "${{ format('{{0}}', x) }}")
	wantString(t, walkTo(t, tree, "on"), "push")
}

func TestFindExpressionSpans_BraceDepth(t *testing.T) {
	cases := []struct {
		name  string
		text  string
		spans [][2]int
	}{
		{"none", "plain: text", nil},
		{
			"single",
			"a${{ x }}b",
			[][2]int{{1, 9}},
		},
		{
			"literal-brace-escape-is-one-span",
			"${{ format('{{0}}', x) }}",
			[][2]int{{0, 25}},
		},
		{
			"two-spans",
			"${{ a }}${{ b }}",
			[][2]int{{0, 8}, {8, 16}},
		},
		{
			"unterminated-bails",
			"${{ broken",
			nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := findExpressionSpans(tc.text)
			if len(got) != len(tc.spans) {
				t.Fatalf("spans = %v, want %v", got, tc.spans)
			}
			for i := range got {
				if got[i] != tc.spans[i] {
					t.Fatalf("span[%d] = %v, want %v", i, got[i], tc.spans[i])
				}
			}
			for _, s := range got {
				sub := tc.text[s[0]:s[1]]
				if !strings.HasPrefix(sub, "${{") || !strings.HasSuffix(sub, "}}") {
					t.Fatalf("span %v -> %q not a complete expression", s, sub)
				}
			}
		})
	}
}

// An unterminated ${{ must not corrupt the rest of the document; the partial
// token parses as an ordinary string scalar.
func TestDecodeWorkflow_UnterminatedExpression(t *testing.T) {
	src := "name: ${{ broken\non: push\n"

	tree, err := DecodeWorkflow(src)
	if err != nil {
		t.Fatalf("DecodeWorkflow error: %v", err)
	}
	wantString(t, walkTo(t, tree, "name"), "${{ broken")
	wantString(t, walkTo(t, tree, "on"), "push")
}

func TestSubstituteRestoreRoundTrip(t *testing.T) {
	t.Run("no-op-without-expression", func(t *testing.T) {
		in := "just plain text\nwith two lines"
		out, originals := substituteExpressions(in)
		if out != in || originals != nil {
			t.Fatalf("expected pass-through, got out=%q originals=%v", out, originals)
		}
	})

	t.Run("single-line-expression-round-trips", func(t *testing.T) {
		in := "with: { ref: ${{ github.sha }} }"
		out, originals := substituteExpressions(in)
		if strings.Contains(out, "${{") {
			t.Fatalf("expression not substituted: %q", out)
		}
		if len(originals) != 1 || originals[0] != "${{ github.sha }}" {
			t.Fatalf("originals = %q", originals)
		}
		if restored := restoreInString(out, originals); restored != in {
			t.Fatalf("round trip = %q, want %q", restored, in)
		}
	})

	t.Run("multiline-placeholder-keeps-line-count", func(t *testing.T) {
		// The invariant is the preserved newline count, not a byte-exact round
		// trip: the padding newlines stay after restore and YAML folding
		// reconciles them.
		in := "x: ${{ a\nb }}\ny: z"
		out, originals := substituteExpressions(in)
		if strings.Contains(out, "${{") {
			t.Fatalf("expression not substituted: %q", out)
		}
		if got, want := strings.Count(out, "\n"), strings.Count(in, "\n"); got != want {
			t.Fatalf("newline count = %d, want %d (line numbers would drift)", got, want)
		}
		if len(originals) != 1 || originals[0] != "${{ a\nb }}" {
			t.Fatalf("originals = %q", originals)
		}
	})

	t.Run("out-of-range-placeholder-left-literal", func(t *testing.T) {
		s := exprPlaceholderPrefix + "5@@ tail"
		if got := restoreInString(s, []string{"only-one"}); got != s {
			t.Fatalf("restore = %q, want unchanged %q", got, s)
		}
	})
}

func TestDecodeWorkflow_EmptyAndCommentOnly(t *testing.T) {
	for _, src := range []string{"", "   \n", "# just a comment\n"} {
		tree, err := DecodeWorkflow(src)
		if err != nil {
			t.Fatalf("DecodeWorkflow(%q) error: %v", src, err)
		}
		if tree != nil {
			t.Fatalf("DecodeWorkflow(%q) = %+v, want nil tree", src, tree)
		}
	}
}

func TestDecodeWorkflow_ScalarTypeResolution(t *testing.T) {
	src := "count: 3\nratio: 1.5\nflag: true\nempty:\nname: text\n"

	tree, err := DecodeWorkflow(src)
	if err != nil {
		t.Fatalf("DecodeWorkflow error: %v", err)
	}

	checks := []struct {
		key  string
		want any
	}{
		{"count", int64(3)},
		{"ratio", 1.5},
		{"flag", true},
		{"empty", nil},
		{"name", "text"},
	}
	for _, c := range checks {
		got := walkTo(t, tree, c.key).Value
		if got != c.want {
			t.Fatalf("%s = %#v (%T), want %#v (%T)", c.key, got, got, c.want, c.want)
		}
	}
}

func TestLineNodeAccessors(t *testing.T) {
	tree, err := DecodeWorkflow("a:\n  b: c\nlist:\n  - one\n  - two\n")
	if err != nil {
		t.Fatalf("DecodeWorkflow error: %v", err)
	}

	t.Run("Field-and-FieldValue", func(t *testing.T) {
		if got := tree.Field("a").FieldValue("b", "DEF"); got != "c" {
			t.Fatalf("FieldValue(a.b) = %v, want c", got)
		}
		if got := tree.FieldValue("missing", "DEF"); got != "DEF" {
			t.Fatalf("FieldValue(missing) = %v, want default DEF", got)
		}
		if scalar := tree.Field("a").Field("b"); scalar.Field("anything") != nil {
			t.Fatal("Field on a scalar should return nil")
		}
	})

	t.Run("nil-receiver-safe", func(t *testing.T) {
		var n *LineNode
		if n.Field("x") != nil {
			t.Fatal("nil.Field should be nil")
		}
		if n.FieldValue("x", "d") != "d" {
			t.Fatal("nil.FieldValue should return default")
		}
		if n.Plain() != nil {
			t.Fatal("nil.Plain should be nil")
		}
		if n.Range() != nil {
			t.Fatal("nil.Range should be nil")
		}
	})

	t.Run("Plain-strips-wrappers", func(t *testing.T) {
		plain, ok := tree.Plain().(map[string]any)
		if !ok {
			t.Fatalf("Plain root = %T, want map[string]any", tree.Plain())
		}
		inner, ok := plain["a"].(map[string]any)
		if !ok || inner["b"] != "c" {
			t.Fatalf("Plain a = %#v, want {b:c}", plain["a"])
		}
		list, ok := plain["list"].([]any)
		if !ok || len(list) != 2 || list[0] != "one" || list[1] != "two" {
			t.Fatalf("Plain list = %#v, want [one two]", plain["list"])
		}
	})

	t.Run("Range", func(t *testing.T) {
		r := tree.Field("a").Field("b").Range()
		if r == nil || *r != (LineRange{2, 2}) {
			t.Fatalf("Range(a.b) = %v, want [2 2]", r)
		}
	})
}
