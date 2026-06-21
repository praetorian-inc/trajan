// pkg/analysis/expression/lexer.go
package expression

import (
	"fmt"
	"regexp"
	"unicode"
)

// Lexer tokenizes GitHub Actions expressions
type Lexer struct {
	input     string
	pos       int
	exprRegex *regexp.Regexp
}

// NewLexer creates a new lexer for the given input
func NewLexer(input string) *Lexer {
	return &Lexer{
		input:     input,
		pos:       0,
		exprRegex: regexp.MustCompile(`\$\{\{\s*(.*?)\s*\}\}`),
	}
}

// Tokenize tokenizes the input string and extracts all expressions
func (l *Lexer) Tokenize() ([]Token, error) {
	// Find all ${{ }} expressions
	matches := l.exprRegex.FindAllStringSubmatchIndex(l.input, -1)
	if len(matches) == 0 {
		return []Token{}, nil
	}

	var allTokens []Token

	for _, match := range matches {
		if len(match) < 4 {
			continue
		}

		// Extract the content inside ${{ }}
		contentStart := match[2]
		contentEnd := match[3]

		content := l.input[contentStart:contentEnd]

		// Tokenize the expression content
		// Use contentStart as the base offset since match[2] is already after "${{ "
		tokens, err := l.tokenizeExpression(content, contentStart)
		if err != nil {
			return nil, fmt.Errorf("tokenizing expression at pos %d: %w", contentStart, err)
		}

		allTokens = append(allTokens, tokens...)
	}

	return allTokens, nil
}

// tokenizeExpression tokenizes the content of a single expression
func (l *Lexer) tokenizeExpression(content string, baseOffset int) ([]Token, error) {
	var tokens []Token
	pos := 0

	// Skip leading whitespace
	for pos < len(content) && unicode.IsSpace(rune(content[pos])) {
		pos++
	}

	for pos < len(content) {
		// Skip whitespace
		for pos < len(content) && unicode.IsSpace(rune(content[pos])) {
			pos++
		}

		if pos >= len(content) {
			break
		}

		ch := content[pos]

		// Check for function call
		if unicode.IsLetter(rune(ch)) || ch == '_' {
			start := pos
			// Read identifier
			for pos < len(content) && (unicode.IsLetter(rune(content[pos])) || unicode.IsDigit(rune(content[pos])) || content[pos] == '_') {
				pos++
			}

			identifier := content[start:pos]

			// Skip whitespace after identifier
			for pos < len(content) && unicode.IsSpace(rune(content[pos])) {
				pos++
			}

			// Check if followed by '(' for function call
			if pos < len(content) && content[pos] == '(' {
				tokens = append(tokens, Token{
					Type:  TokenFunction,
					Value: identifier,
					Start: baseOffset + start,
					End:   baseOffset + pos,
				})
				continue
			}

			// Otherwise, it's a context reference
			// Read the full dotted path
			dotStart := start
			pos = start
			for pos < len(content) {
				if content[pos] == '.' {
					pos++
					// Allow wildcards in context paths
					if pos < len(content) && content[pos] == '*' {
						pos++
					}
					// Continue reading identifier
					for pos < len(content) && (unicode.IsLetter(rune(content[pos])) || unicode.IsDigit(rune(content[pos])) || content[pos] == '_') {
						pos++
					}
				} else if unicode.IsLetter(rune(content[pos])) || unicode.IsDigit(rune(content[pos])) || content[pos] == '_' {
					pos++
				} else {
					break
				}
			}

			contextPath := content[dotStart:pos]
			tokens = append(tokens, Token{
				Type:  TokenContext,
				Value: contextPath,
				Start: baseOffset + dotStart,
				End:   baseOffset + pos,
			})
			continue
		}

		// Check for string literals (single-quoted only, '' escapes a single quote)
		if ch == '\'' {
			start := pos
			pos++ // skip opening quote
			for pos < len(content) {
				if content[pos] == '\'' {
					// Check if next char is also a single quote (escaped quote)
					if pos+1 < len(content) && content[pos+1] == '\'' {
						pos += 2 // skip both quotes, continue
						continue
					}
					// Otherwise it's the closing quote
					pos++
					break
				}
				pos++
			}

			tokens = append(tokens, Token{
				Type:  TokenLiteral,
				Value: content[start:pos],
				Start: baseOffset + start,
				End:   baseOffset + pos,
			})
			continue
		}

		// Check for parentheses
		if ch == '(' || ch == ')' {
			tokens = append(tokens, Token{
				Type:  TokenParen,
				Value: string(ch),
				Start: baseOffset + pos,
				End:   baseOffset + pos + 1,
			})
			pos++
			continue
		}

		// Check for operators
		if ch == ',' {
			tokens = append(tokens, Token{
				Type:  TokenOperator,
				Value: ",",
				Start: baseOffset + pos,
				End:   baseOffset + pos + 1,
			})
			pos++
			continue
		}

		// Check for comparison operators
		if ch == '=' || ch == '!' || ch == '<' || ch == '>' {
			start := pos
			pos++
			if pos < len(content) && content[pos] == '=' {
				pos++
			}
			tokens = append(tokens, Token{
				Type:  TokenOperator,
				Value: content[start:pos],
				Start: baseOffset + start,
				End:   baseOffset + pos,
			})
			continue
		}

		// Check for logical operators
		if ch == '&' || ch == '|' {
			start := pos
			pos++
			if pos < len(content) && content[pos] == ch {
				pos++
			}
			tokens = append(tokens, Token{
				Type:  TokenOperator,
				Value: content[start:pos],
				Start: baseOffset + start,
				End:   baseOffset + pos,
			})
			continue
		}

		// Unknown character, skip it
		pos++
	}

	return tokens, nil
}
