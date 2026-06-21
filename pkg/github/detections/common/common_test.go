package common

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/praetorian-inc/trajan/pkg/analysis/graph"
)

func TestInjectableContexts_Contains(t *testing.T) {
	found := false
	for _, ctx := range InjectableContexts {
		if ctx == "github.event.comment.body" {
			found = true
			break
		}
	}
	assert.True(t, found, "Should contain github.event.comment.body")
}

func TestZeroClickTriggers_IssueComment(t *testing.T) {
	assert.True(t, ZeroClickTriggers[graph.TagIssueComment])
}

func TestExpressionRegex_Matches(t *testing.T) {
	tests := []struct {
		input string
		match bool
	}{
		{`echo "${{ github.event.comment.body }}"`, true},
		{`echo "hello world"`, false},
		{`${{ github.sha }}`, true},
	}

	for _, tt := range tests {
		matches := ExpressionRegex.FindAllString(tt.input, -1)
		if tt.match {
			assert.NotEmpty(t, matches, "Should match: %s", tt.input)
		} else {
			assert.Empty(t, matches, "Should not match: %s", tt.input)
		}
	}
}
