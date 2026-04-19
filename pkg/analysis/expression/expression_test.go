// pkg/analysis/expression/expression_test.go
package expression

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewLexer(t *testing.T) {
	lexer := NewLexer("test input")
	assert.NotNil(t, lexer)
}

func TestLexer_SimpleContextRef(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []Token
	}{
		{
			name:  "simple github context",
			input: "${{ github.event.action }}",
			expected: []Token{
				{Type: TokenContext, Value: "github.event.action", Start: 4, End: 23},
			},
		},
		{
			name:  "nested path",
			input: "${{ github.event.pull_request.title }}",
			expected: []Token{
				{Type: TokenContext, Value: "github.event.pull_request.title", Start: 4, End: 35},
			},
		},
		{
			name:  "inputs context",
			input: "${{ inputs.my_var }}",
			expected: []Token{
				{Type: TokenContext, Value: "inputs.my_var", Start: 4, End: 17},
			},
		},
		{
			name:  "env context",
			input: "${{ env.MY_VAR }}",
			expected: []Token{
				{Type: TokenContext, Value: "env.MY_VAR", Start: 4, End: 14},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lexer := NewLexer(tt.input)
			tokens, err := lexer.Tokenize()
			require.NoError(t, err)
			assert.Equal(t, tt.expected, tokens)
		})
	}
}

func TestLexer_FunctionCalls(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []Token
	}{
		{
			name:  "contains function",
			input: "${{ contains(github.event.comment.body, '/deploy') }}",
			expected: []Token{
				{Type: TokenFunction, Value: "contains", Start: 4, End: 12},
				{Type: TokenParen, Value: "(", Start: 12, End: 13},
				{Type: TokenContext, Value: "github.event.comment.body", Start: 13, End: 38},
				{Type: TokenOperator, Value: ",", Start: 38, End: 39},
				{Type: TokenLiteral, Value: "'/deploy'", Start: 40, End: 49},
				{Type: TokenParen, Value: ")", Start: 49, End: 50},
			},
		},
		{
			name:  "success function",
			input: "${{ success() }}",
			expected: []Token{
				{Type: TokenFunction, Value: "success", Start: 4, End: 11},
				{Type: TokenParen, Value: "(", Start: 11, End: 12},
				{Type: TokenParen, Value: ")", Start: 12, End: 13},
			},
		},
		{
			name:  "fromJson function",
			input: "${{ fromJson(steps.build.outputs.result) }}",
			expected: []Token{
				{Type: TokenFunction, Value: "fromJson", Start: 4, End: 12},
				{Type: TokenParen, Value: "(", Start: 12, End: 13},
				{Type: TokenContext, Value: "steps.build.outputs.result", Start: 13, End: 39},
				{Type: TokenParen, Value: ")", Start: 39, End: 40},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lexer := NewLexer(tt.input)
			tokens, err := lexer.Tokenize()
			require.NoError(t, err)
			assert.Equal(t, tt.expected, tokens)
		})
	}
}

func TestLexer_MultipleExpressions(t *testing.T) {
	input := "echo ${{ github.event.action }} and ${{ github.ref }}"

	lexer := NewLexer(input)
	tokens, err := lexer.Tokenize()
	require.NoError(t, err)

	// Should extract both expressions
	assert.Len(t, tokens, 2)
	assert.Equal(t, "github.event.action", tokens[0].Value)
	assert.Equal(t, "github.ref", tokens[1].Value)
}

func TestEvaluator_ExtractAll(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		expectedCount int
		expectedRefs  []string
	}{
		{
			name:          "single expression",
			input:         "${{ github.event.action }}",
			expectedCount: 1,
			expectedRefs:  []string{"github.event.action"},
		},
		{
			name:          "multiple expressions",
			input:         "echo ${{ github.event.action }} and ${{ github.ref }}",
			expectedCount: 2,
			expectedRefs:  []string{"github.event.action", "github.ref"},
		},
		{
			name:          "no expressions",
			input:         "plain text without expressions",
			expectedCount: 0,
			expectedRefs:  []string{},
		},
		{
			name:          "nested expression in function",
			input:         "${{ contains(github.event.comment.body, '/deploy') }}",
			expectedCount: 1,
			expectedRefs:  []string{"github.event.comment.body"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evaluator := NewEvaluator()
			expressions, err := evaluator.ExtractAll(tt.input)
			require.NoError(t, err)
			assert.Len(t, expressions, tt.expectedCount)

			if tt.expectedCount > 0 {
				var refs []string
				for _, expr := range expressions {
					for _, ref := range expr.References {
						refs = append(refs, ref.Context+"."+joinPath(ref.Path))
					}
				}
				assert.Equal(t, tt.expectedRefs, refs)
			}
		})
	}
}

func TestExpression_Parse(t *testing.T) {
	tests := []struct {
		name              string
		input             string
		expectedRefs      int
		expectedFunctions int
		expectedContexts  []string
	}{
		{
			name:              "simple context",
			input:             "${{ github.event.action }}",
			expectedRefs:      1,
			expectedFunctions: 0,
			expectedContexts:  []string{"github"},
		},
		{
			name:              "contains function",
			input:             "${{ contains(github.event.comment.body, '/deploy') }}",
			expectedRefs:      1,
			expectedFunctions: 1,
			expectedContexts:  []string{"github"},
		},
		{
			name:              "env and github",
			input:             "${{ env.MY_VAR }}",
			expectedRefs:      1,
			expectedFunctions: 0,
			expectedContexts:  []string{"env"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evaluator := NewEvaluator()
			expr, err := evaluator.Parse(tt.input)
			require.NoError(t, err)
			assert.NotNil(t, expr)
			assert.Len(t, expr.References, tt.expectedRefs)
			assert.Len(t, expr.Functions, tt.expectedFunctions)

			if tt.expectedRefs > 0 {
				var contexts []string
				for _, ref := range expr.References {
					contexts = append(contexts, ref.Context)
				}
				assert.Equal(t, tt.expectedContexts, contexts)
			}
		})
	}
}

func TestContextRef_IsTaint(t *testing.T) {
	tests := []struct {
		name     string
		ref      ContextRef
		expected bool
	}{
		{
			name: "github.event.comment.body is tainted",
			ref: ContextRef{
				Context: "github",
				Path:    []string{"event", "comment", "body"},
			},
			expected: true,
		},
		{
			name: "github.event.pull_request.title is tainted",
			ref: ContextRef{
				Context: "github",
				Path:    []string{"event", "pull_request", "title"},
			},
			expected: true,
		},
		{
			name: "github.sha is not tainted",
			ref: ContextRef{
				Context: "github",
				Path:    []string{"sha"},
			},
			expected: false,
		},
		{
			name: "secrets context is not tainted",
			ref: ContextRef{
				Context: "secrets",
				Path:    []string{"GITHUB_TOKEN"},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isTaint := tt.ref.IsTainted()
			assert.Equal(t, tt.expected, isTaint)
		})
	}
}

// Helper function for test
func joinPath(path []string) string {
	if len(path) == 0 {
		return ""
	}
	result := path[0]
	for i := 1; i < len(path); i++ {
		result += "." + path[i]
	}
	return result
}

// ==============================================================================
// Issue #1: AST Building Tests
// ==============================================================================

func TestBuildAST(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		expectedType NodeType
		wantChildren int
	}{
		{
			name:         "simple identifier",
			input:        "${{ github.event.action }}",
			expectedType: NodeIdentifier,
			wantChildren: 0,
		},
		{
			name:         "comparison",
			input:        "${{ github.event.action == 'opened' }}",
			expectedType: NodeComparison,
			wantChildren: 2, // left and right operands
		},
		{
			name:         "logical and",
			input:        "${{ github.event.action == 'opened' && contains(github.event.comment.body, '/deploy') }}",
			expectedType: NodeLogicalAnd,
			wantChildren: 2, // comparison and function call
		},
		{
			name:         "function call",
			input:        "${{ contains(github.event.comment.body, '/deploy') }}",
			expectedType: NodeFunctionCall,
			wantChildren: 2, // function name + arguments
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evaluator := NewEvaluator()
			expr, err := evaluator.Parse(tt.input)
			require.NoError(t, err)

			// Build AST from tokens
			ast, err := buildAST(expr.Tokens)
			require.NoError(t, err)
			assert.NotNil(t, ast)
			assert.Equal(t, tt.expectedType, ast.Type)
			assert.Len(t, ast.Children, tt.wantChildren)
		})
	}
}

// ==============================================================================
// Issue #2: Evaluation Logic Tests
// ==============================================================================

func TestEvaluate(t *testing.T) {
	tests := []struct {
		name    string
		expr    string
		want    bool
		wantErr bool
	}{
		{
			name: "github.event.action equals opened",
			expr: "${{ github.event.action == 'opened' }}",
			want: true, // FlexibleAction matches 'opened'
		},
		{
			name: "contains with wildcard body",
			expr: "${{ contains(github.event.comment.body, '/deploy') }}",
			want: true, // Wildcard matches anything
		},
		{
			name: "fork check",
			expr: "${{ github.event.pull_request.head.repo.fork == false }}",
			want: false, // Fork defaults to true
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evaluator := NewEvaluator()
			got, err := evaluator.Evaluate(tt.expr)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestEvaluateCondition(t *testing.T) {
	tests := []struct {
		name     string
		cond     string
		want     bool
		wantConf Confidence
	}{
		{
			name:     "success always reachable",
			cond:     "success()",
			want:     true,
			wantConf: ConfidenceHigh,
		},
		{
			name:     "failure reachable",
			cond:     "failure()",
			want:     true,
			wantConf: ConfidenceHigh,
		},
		{
			name:     "canceled not reachable",
			cond:     "canceled()",
			want:     false,
			wantConf: ConfidenceHigh,
		},
		{
			name:     "always reachable",
			cond:     "always()",
			want:     true,
			wantConf: ConfidenceHigh,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evaluator := NewEvaluator()
			got, conf, err := evaluator.EvaluateCondition(tt.cond)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
			assert.Equal(t, tt.wantConf, conf)
		})
	}
}

// ==============================================================================
// Issue #3: Value Interface Tests
// ==============================================================================

func TestWildcard(t *testing.T) {
	wildcard := NewWildcard("github.event.comment.body")

	tests := []struct {
		name  string
		other Value
		want  bool
	}{
		{
			name:  "wildcard matches any string",
			other: NewStringValue("anything"),
			want:  true,
		},
		{
			name:  "wildcard matches itself",
			other: NewWildcard("github.event.comment.body"),
			want:  true,
		},
		{
			name:  "wildcard doesn't match different context",
			other: NewWildcard("github.event.issue.body"),
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, wildcard.Equals(tt.other))
		})
	}
}

func TestFlexibleAction(t *testing.T) {
	action := NewFlexibleAction([]string{"opened", "edited", "synchronize"})

	tests := []struct {
		name  string
		other Value
		want  bool
	}{
		{
			name:  "matches opened",
			other: NewStringValue("opened"),
			want:  true,
		},
		{
			name:  "matches edited",
			other: NewStringValue("edited"),
			want:  true,
		},
		{
			name:  "doesn't match closed",
			other: NewStringValue("closed"),
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, action.Equals(tt.other))
		})
	}
}

func TestBoolValue(t *testing.T) {
	trueVal := NewBoolValue(true)
	falseVal := NewBoolValue(false)

	assert.True(t, trueVal.IsTruthy())
	assert.False(t, falseVal.IsTruthy())
	assert.True(t, trueVal.Equals(NewBoolValue(true)))
	assert.False(t, trueVal.Equals(falseVal))
}

// ==============================================================================
// Issue #4: Function Implementations Tests
// ==============================================================================

func TestFunctionContains(t *testing.T) {
	tests := []struct {
		name string
		a    Value
		b    Value
		want bool
	}{
		{
			name: "string contains substring",
			a:    NewStringValue("/deploy now"),
			b:    NewStringValue("/deploy"),
			want: true,
		},
		{
			name: "wildcard contains anything",
			a:    NewWildcard("github.event.comment.body"),
			b:    NewStringValue("/deploy"),
			want: true,
		},
		{
			name: "string doesn't contain substring",
			a:    NewStringValue("hello world"),
			b:    NewStringValue("/deploy"),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := fnContains([]Value{tt.a, tt.b})
			require.NoError(t, err)
			assert.Equal(t, tt.want, got.IsTruthy())
		})
	}
}

func TestFunctionStartsWith(t *testing.T) {
	tests := []struct {
		name string
		a    Value
		b    Value
		want bool
	}{
		{
			name: "string starts with prefix",
			a:    NewStringValue("/deploy now"),
			b:    NewStringValue("/deploy"),
			want: true,
		},
		{
			name: "string doesn't start with prefix",
			a:    NewStringValue("hello /deploy"),
			b:    NewStringValue("/deploy"),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := fnStartsWith([]Value{tt.a, tt.b})
			require.NoError(t, err)
			assert.Equal(t, tt.want, got.IsTruthy())
		})
	}
}

func TestFunctionSuccess(t *testing.T) {
	result, err := fnSuccess([]Value{})
	require.NoError(t, err)
	assert.True(t, result.IsTruthy())
}

func TestFunctionFailure(t *testing.T) {
	result, err := fnFailure([]Value{})
	require.NoError(t, err)
	assert.True(t, result.IsTruthy())
}

func TestFunctionAlways(t *testing.T) {
	result, err := fnAlways([]Value{})
	require.NoError(t, err)
	assert.True(t, result.IsTruthy())
}

func TestFunctionCancelled(t *testing.T) {
	result, err := fnCancelled([]Value{})
	require.NoError(t, err)
	assert.False(t, result.IsTruthy())
}

// ==============================================================================
// Issue #5: Standard Variables Tests
// ==============================================================================

func TestStandardVariables(t *testing.T) {
	vars := StandardVariables()

	tests := []struct {
		name     string
		varName  string
		wantType string // "wildcard", "flexible", "bool", "string"
	}{
		{
			name:     "comment body is wildcard",
			varName:  "github.event.comment.body",
			wantType: "wildcard",
		},
		{
			name:     "pull request title is wildcard",
			varName:  "github.event.pull_request.title",
			wantType: "wildcard",
		},
		{
			name:     "event action is flexible",
			varName:  "github.event.action",
			wantType: "flexible",
		},
		{
			name:     "fork defaults to true",
			varName:  "github.event.pull_request.head.repo.fork",
			wantType: "bool",
		},
		{
			name:     "merged defaults to false",
			varName:  "github.event.pull_request.merged",
			wantType: "bool",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			val, ok := vars[tt.varName]
			assert.True(t, ok, "variable should exist in StandardVariables")
			assert.NotNil(t, val)

			switch tt.wantType {
			case "wildcard":
				_, ok := val.(*Wildcard)
				assert.True(t, ok, "should be Wildcard type")
			case "flexible":
				_, ok := val.(*FlexibleAction)
				assert.True(t, ok, "should be FlexibleAction type")
			case "bool":
				_, ok := val.(*BoolValue)
				assert.True(t, ok, "should be BoolValue type")
			}
		})
	}
}
