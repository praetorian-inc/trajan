// pkg/analysis/expression/expression.go
package expression

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/praetorian-inc/trajan/pkg/detections/shared/taintsources"
)

// TokenType represents the type of token in an expression
type TokenType int

const (
	// TokenLiteral represents a literal value (string, number, boolean)
	TokenLiteral TokenType = iota
	// TokenOperator represents an operator (==, !=, &&, ||, etc.)
	TokenOperator
	// TokenFunction represents a function call (contains, fromJson, etc.)
	TokenFunction
	// TokenContext represents a context reference (github.*, inputs.*, etc.)
	TokenContext
	// TokenParen represents parentheses
	TokenParen
)

// NodeType represents the type of AST node
type NodeType string

const (
	// NodeIdentifier represents an identifier (variable reference)
	NodeIdentifier NodeType = "identifier"
	// NodeString represents a string literal
	NodeString NodeType = "string"
	// NodeLogicalAnd represents a logical AND operation
	NodeLogicalAnd NodeType = "logical_and"
	// NodeLogicalOr represents a logical OR operation
	NodeLogicalOr NodeType = "logical_or"
	// NodeComparison represents a comparison operation (==, !=, <, >, etc.)
	NodeComparison NodeType = "comparison"
	// NodeUnaryNot represents a unary NOT operation
	NodeUnaryNot NodeType = "unary_not"
	// NodeFunctionCall represents a function call
	NodeFunctionCall NodeType = "function_call"
)

// Node represents an AST node
type Node struct {
	Type     NodeType
	Value    string
	Children []*Node
}

// Confidence represents confidence level in evaluation result
type Confidence int

const (
	// ConfidenceLow indicates low confidence
	ConfidenceLow Confidence = iota
	// ConfidenceMedium indicates medium confidence
	ConfidenceMedium
	// ConfidenceHigh indicates high confidence
	ConfidenceHigh
)

// Value represents a value that can be evaluated
type Value interface {
	// Equals checks equality with another value
	Equals(other Value) bool
	// String returns string representation
	String() string
	// IsTruthy returns boolean evaluation
	IsTruthy() bool
}

// Token represents a lexical token in an expression
type Token struct {
	Type  TokenType
	Value string
	Start int // Start position in original string
	End   int // End position in original string
}

// Expression represents a parsed GitHub Actions expression
type Expression struct {
	Raw        string         // Original expression string including ${{ }}
	Tokens     []Token        // Lexical tokens
	References []ContextRef   // Context references extracted
	Functions  []FunctionCall // Function calls extracted
}

// ContextRef represents a reference to a GitHub Actions context
type ContextRef struct {
	Context string   // The context type (github, inputs, env, secrets, steps, etc.)
	Path    []string // Path components (e.g., ["event", "pull_request", "title"])
	IsTaint bool     // Whether this reference is user-controllable (tainted)
}

// FunctionCall represents a function call in an expression
type FunctionCall struct {
	Name      string       // Function name (contains, fromJson, etc.)
	Arguments []Expression // Parsed arguments
}

// Evaluator evaluates GitHub Actions expressions
type Evaluator struct {
	exprRegex    *regexp.Regexp
	contextRegex *regexp.Regexp
	funcRegex    *regexp.Regexp
	variables    map[string]Value
}

// NewEvaluator creates a new expression evaluator with standard GitHub context
func NewEvaluator() *Evaluator {
	return &Evaluator{
		// Pattern matches ${{ ... }}
		exprRegex: regexp.MustCompile(`\$\{\{\s*(.*?)\s*\}\}`),
		// Pattern matches context references like github.event.action
		contextRegex: regexp.MustCompile(`([a-zA-Z_][a-zA-Z0-9_]*)(?:\.([a-zA-Z_*][a-zA-Z0-9_*.]*))?`),
		// Pattern matches function calls like contains(...)
		funcRegex: regexp.MustCompile(`([a-zA-Z_][a-zA-Z0-9_]*)\s*\(`),
		variables: StandardVariables(),
	}
}

// ExtractAll extracts all expressions from a string
func (e *Evaluator) ExtractAll(input string) ([]*Expression, error) {
	matches := e.exprRegex.FindAllStringSubmatch(input, -1)
	if len(matches) == 0 {
		return []*Expression{}, nil
	}

	var expressions []*Expression
	for _, match := range matches {
		if len(match) < 2 {
			continue
		}

		expr, err := e.Parse(match[0])
		if err != nil {
			return nil, fmt.Errorf("parsing expression %q: %w", match[0], err)
		}
		expressions = append(expressions, expr)
	}

	return expressions, nil
}

// Parse parses a single expression
func (e *Evaluator) Parse(input string) (*Expression, error) {
	expr := &Expression{
		Raw:        input,
		References: []ContextRef{},
		Functions:  []FunctionCall{},
	}

	// Create a lexer to tokenize
	lexer := NewLexer(input)
	tokens, err := lexer.Tokenize()
	if err != nil {
		return nil, fmt.Errorf("tokenizing: %w", err)
	}
	expr.Tokens = tokens

	// Extract context references from tokens
	for _, token := range tokens {
		if token.Type == TokenContext {
			ref := e.parseContextRef(token.Value)
			expr.References = append(expr.References, ref)
		}
	}

	// Extract function calls from tokens
	for i, token := range tokens {
		if token.Type == TokenFunction {
			funcCall := FunctionCall{
				Name:      token.Value,
				Arguments: []Expression{}, // TODO: Parse arguments
			}
			expr.Functions = append(expr.Functions, funcCall)
			// Skip to end of function call
			for j := i + 1; j < len(tokens) && tokens[j].Type != TokenParen; j++ {
				// Advance
			}
		}
	}

	return expr, nil
}

// parseContextRef parses a context reference string into a ContextRef
func (e *Evaluator) parseContextRef(ref string) ContextRef {
	parts := strings.Split(ref, ".")
	if len(parts) == 0 {
		return ContextRef{}
	}

	context := parts[0]
	path := parts[1:]

	// Determine if this is a tainted (user-controllable) reference
	isTaint := e.isTaintedRef(context, path)

	return ContextRef{
		Context: context,
		Path:    path,
		IsTaint: isTaint,
	}
}

// isTaintedRef determines if a context reference is user-controllable
func (e *Evaluator) isTaintedRef(context string, path []string) bool {
	fullRef := context + "." + strings.Join(path, ".")
	for _, tainted := range taintsources.GitHubTaintedContexts {
		if strings.HasPrefix(fullRef, tainted) {
			return true
		}
	}
	return false
}

// IsTainted returns whether this context reference is user-controllable
func (c *ContextRef) IsTainted() bool {
	fullRef := c.Context + "." + strings.Join(c.Path, ".")
	for _, tainted := range taintsources.GitHubTaintedContexts {
		if strings.HasPrefix(fullRef, tainted) {
			return true
		}
	}
	return false
}

// Evaluate evaluates an expression and returns a boolean result
func (e *Evaluator) Evaluate(expr string) (bool, error) {
	// If expression doesn't have ${{ }}, wrap it
	if !strings.Contains(expr, "${{") {
		expr = "${{ " + expr + " }}"
	}

	// Parse the expression
	parsed, err := e.Parse(expr)
	if err != nil {
		return false, fmt.Errorf("parsing expression: %w", err)
	}

	// Build AST from tokens
	ast, err := buildAST(parsed.Tokens)
	if err != nil {
		return false, fmt.Errorf("building AST: %w", err)
	}

	// Evaluate the AST
	result, err := e.evaluateNode(ast)
	if err != nil {
		return false, fmt.Errorf("evaluating AST: %w", err)
	}

	return result.IsTruthy(), nil
}

// EvaluateCondition evaluates an if: condition and returns reachability with confidence
func (e *Evaluator) EvaluateCondition(condition string) (bool, Confidence, error) {
	// Parse and evaluate
	reachable, err := e.Evaluate(condition)
	if err != nil {
		return false, ConfidenceLow, err
	}

	// For now, all evaluations have high confidence
	// In the future, this could be more sophisticated based on wildcards, etc.
	return reachable, ConfidenceHigh, nil
}

// buildAST builds an AST from a list of tokens
func buildAST(tokens []Token) (*Node, error) {
	if len(tokens) == 0 {
		return nil, fmt.Errorf("empty token list")
	}

	// Simple recursive descent parser
	pos := 0
	return parseExpression(tokens, &pos)
}

// parseExpression parses a logical OR expression (lowest precedence)
func parseExpression(tokens []Token, pos *int) (*Node, error) {
	left, err := parseLogicalAnd(tokens, pos)
	if err != nil {
		return nil, err
	}

	// Check for || operator
	for *pos < len(tokens) && tokens[*pos].Type == TokenOperator && tokens[*pos].Value == "||" {
		*pos++ // consume ||
		right, err := parseLogicalAnd(tokens, pos)
		if err != nil {
			return nil, err
		}
		left = &Node{
			Type:     NodeLogicalOr,
			Value:    "||",
			Children: []*Node{left, right},
		}
	}

	return left, nil
}

// parseLogicalAnd parses a logical AND expression
func parseLogicalAnd(tokens []Token, pos *int) (*Node, error) {
	left, err := parseComparison(tokens, pos)
	if err != nil {
		return nil, err
	}

	// Check for && operator
	for *pos < len(tokens) && tokens[*pos].Type == TokenOperator && tokens[*pos].Value == "&&" {
		*pos++ // consume &&
		right, err := parseComparison(tokens, pos)
		if err != nil {
			return nil, err
		}
		left = &Node{
			Type:     NodeLogicalAnd,
			Value:    "&&",
			Children: []*Node{left, right},
		}
	}

	return left, nil
}

// parseComparison parses a comparison expression
func parseComparison(tokens []Token, pos *int) (*Node, error) {
	left, err := parsePrimary(tokens, pos)
	if err != nil {
		return nil, err
	}

	// Check for comparison operator
	if *pos < len(tokens) && tokens[*pos].Type == TokenOperator {
		op := tokens[*pos].Value
		if op == "==" || op == "!=" || op == "<" || op == ">" || op == "<=" || op == ">=" {
			*pos++ // consume operator
			right, err := parsePrimary(tokens, pos)
			if err != nil {
				return nil, err
			}
			return &Node{
				Type:     NodeComparison,
				Value:    op,
				Children: []*Node{left, right},
			}, nil
		}
	}

	return left, nil
}

// parsePrimary parses a primary expression (function call, identifier, literal)
func parsePrimary(tokens []Token, pos *int) (*Node, error) {
	if *pos >= len(tokens) {
		return nil, fmt.Errorf("unexpected end of tokens")
	}

	token := tokens[*pos]

	// Function call
	if token.Type == TokenFunction {
		funcName := token.Value
		*pos++ // consume function name

		// Expect opening paren
		if *pos >= len(tokens) || tokens[*pos].Type != TokenParen || tokens[*pos].Value != "(" {
			return nil, fmt.Errorf("expected '(' after function name")
		}
		*pos++ // consume (

		// Parse arguments
		var args []*Node
		for *pos < len(tokens) && (tokens[*pos].Type != TokenParen || tokens[*pos].Value != ")") {
			// Skip commas
			if tokens[*pos].Type == TokenOperator && tokens[*pos].Value == "," {
				*pos++
				continue
			}

			arg, err := parsePrimary(tokens, pos)
			if err != nil {
				return nil, err
			}
			args = append(args, arg)
		}

		// Consume closing paren
		if *pos >= len(tokens) || tokens[*pos].Type != TokenParen || tokens[*pos].Value != ")" {
			return nil, fmt.Errorf("expected ')' after function arguments")
		}
		*pos++

		return &Node{
			Type:     NodeFunctionCall,
			Value:    funcName,
			Children: args,
		}, nil
	}

	// Literal (string)
	if token.Type == TokenLiteral {
		*pos++
		// Remove quotes from string literals
		val := token.Value
		if strings.HasPrefix(val, "'") && strings.HasSuffix(val, "'") {
			val = val[1 : len(val)-1]
			// Unescape doubled single quotes
			val = strings.ReplaceAll(val, "''", "'")
		}
		return &Node{
			Type:  NodeString,
			Value: val,
		}, nil
	}

	// Context reference (identifier)
	if token.Type == TokenContext {
		*pos++
		return &Node{
			Type:  NodeIdentifier,
			Value: token.Value,
		}, nil
	}

	// Parenthesized expression
	if token.Type == TokenParen && token.Value == "(" {
		*pos++ // consume (
		expr, err := parseExpression(tokens, pos)
		if err != nil {
			return nil, err
		}
		// Expect closing paren
		if *pos >= len(tokens) || tokens[*pos].Type != TokenParen || tokens[*pos].Value != ")" {
			return nil, fmt.Errorf("expected ')' after expression")
		}
		*pos++
		return expr, nil
	}

	return nil, fmt.Errorf("unexpected token: %v", token)
}

// evaluateNode evaluates an AST node
func (e *Evaluator) evaluateNode(node *Node) (Value, error) {
	switch node.Type {
	case NodeIdentifier:
		// Look up variable in context
		if val, ok := e.variables[node.Value]; ok {
			return val, nil
		}
		// Default to string value
		return NewStringValue(node.Value), nil

	case NodeString:
		return NewStringValue(node.Value), nil

	case NodeComparison:
		if len(node.Children) != 2 {
			return nil, fmt.Errorf("comparison node must have 2 children")
		}
		left, err := e.evaluateNode(node.Children[0])
		if err != nil {
			return nil, err
		}
		right, err := e.evaluateNode(node.Children[1])
		if err != nil {
			return nil, err
		}

		// Perform comparison
		switch node.Value {
		case "==":
			return NewBoolValue(left.Equals(right)), nil
		case "!=":
			return NewBoolValue(!left.Equals(right)), nil
		case "<", ">", "<=", ">=":
			if _, ok := left.(*Wildcard); ok {
				return NewBoolValue(true), nil
			}
			if _, ok := right.(*Wildcard); ok {
				return NewBoolValue(true), nil
			}
			leftNum, leftErr := strconv.ParseFloat(left.String(), 64)
			rightNum, rightErr := strconv.ParseFloat(right.String(), 64)
			if leftErr == nil && rightErr == nil {
				switch node.Value {
				case "<":
					return NewBoolValue(leftNum < rightNum), nil
				case ">":
					return NewBoolValue(leftNum > rightNum), nil
				case "<=":
					return NewBoolValue(leftNum <= rightNum), nil
				case ">=":
					return NewBoolValue(leftNum >= rightNum), nil
				}
			}
			return NewBoolValue(true), nil
		default:
			return nil, fmt.Errorf("unsupported comparison operator: %s", node.Value)
		}

	case NodeLogicalAnd:
		if len(node.Children) != 2 {
			return nil, fmt.Errorf("logical AND node must have 2 children")
		}
		left, err := e.evaluateNode(node.Children[0])
		if err != nil {
			return nil, err
		}
		if !left.IsTruthy() {
			return NewBoolValue(false), nil
		}
		right, err := e.evaluateNode(node.Children[1])
		if err != nil {
			return nil, err
		}
		return NewBoolValue(right.IsTruthy()), nil

	case NodeLogicalOr:
		if len(node.Children) != 2 {
			return nil, fmt.Errorf("logical OR node must have 2 children")
		}
		left, err := e.evaluateNode(node.Children[0])
		if err != nil {
			return nil, err
		}
		if left.IsTruthy() {
			return NewBoolValue(true), nil
		}
		right, err := e.evaluateNode(node.Children[1])
		if err != nil {
			return nil, err
		}
		return NewBoolValue(right.IsTruthy()), nil

	case NodeFunctionCall:
		// Evaluate function arguments
		var args []Value
		for _, child := range node.Children {
			arg, err := e.evaluateNode(child)
			if err != nil {
				return nil, err
			}
			args = append(args, arg)
		}

		// Call the function
		return callFunction(node.Value, args)

	default:
		return nil, fmt.Errorf("unsupported node type: %s", node.Type)
	}
}

// TaintInfo represents taint information for an expression
type TaintInfo struct {
	IsTainted       bool
	Sources         []string // Tainted sources referenced
	Confidence      Confidence
	PropagationPath []string
}

// GetTaintInfo analyzes an expression for taint information
func (e *Evaluator) GetTaintInfo(expr *Expression) *TaintInfo {
	info := &TaintInfo{
		IsTainted: false,
		Sources:   []string{},
	}

	for _, ref := range expr.References {
		if ref.IsTainted() {
			info.IsTainted = true
			info.Sources = append(info.Sources, ref.Context+"."+strings.Join(ref.Path, "."))
		}
	}

	if info.IsTainted {
		info.Confidence = ConfidenceHigh
	}

	return info
}

// EvaluateWithTaint evaluates an expression and returns taint information
func (e *Evaluator) EvaluateWithTaint(expr string) (bool, *TaintInfo, error) {
	parsed, err := e.Parse(expr)
	if err != nil {
		return false, nil, err
	}

	taintInfo := e.GetTaintInfo(parsed)

	result, err := e.Evaluate(expr)
	if err != nil {
		return false, taintInfo, err
	}

	return result, taintInfo, nil
}
