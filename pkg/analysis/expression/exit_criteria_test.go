// pkg/analysis/expression/exit_criteria_test.go
package expression

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestExitCriteria verifies all 4 exit criteria from the architecture plan
func TestExitCriteria(t *testing.T) {
	evaluator := NewEvaluator()

	// Exit Criterion 1: Can parse ${{ github.event.action == 'opened' }}
	t.Run("parse github.event.action == opened", func(t *testing.T) {
		expr := "${{ github.event.action == 'opened' }}"
		parsed, err := evaluator.Parse(expr)
		require.NoError(t, err)
		assert.NotNil(t, parsed)
		assert.Greater(t, len(parsed.Tokens), 0)

		// Build AST
		ast, err := buildAST(parsed.Tokens)
		require.NoError(t, err)
		assert.NotNil(t, ast)
	})

	// Exit Criterion 2: Can evaluate contains(github.event.comment.body, '/deploy')
	t.Run("evaluate contains with wildcard", func(t *testing.T) {
		expr := "${{ contains(github.event.comment.body, '/deploy') }}"
		result, err := evaluator.Evaluate(expr)
		require.NoError(t, err)
		assert.True(t, result, "Wildcard should match '/deploy'")
	})

	// Exit Criterion 3: Returns correct reachability for if: success()
	t.Run("reachability for success()", func(t *testing.T) {
		reachable, confidence, err := evaluator.EvaluateCondition("success()")
		require.NoError(t, err)
		assert.True(t, reachable, "success() should be reachable")
		assert.Equal(t, ConfidenceHigh, confidence)
	})

	// Exit Criterion 4: Returns correct reachability for if: failure()
	t.Run("reachability for failure()", func(t *testing.T) {
		reachable, confidence, err := evaluator.EvaluateCondition("failure()")
		require.NoError(t, err)
		assert.True(t, reachable, "failure() should be reachable (can be induced)")
		assert.Equal(t, ConfidenceHigh, confidence)
	})

	// Additional verification: canceled() should NOT be reachable
	t.Run("reachability for canceled()", func(t *testing.T) {
		reachable, confidence, err := evaluator.EvaluateCondition("canceled()")
		require.NoError(t, err)
		assert.False(t, reachable, "canceled() should NOT be reachable")
		assert.Equal(t, ConfidenceHigh, confidence)
	})
}
