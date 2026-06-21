package common

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/praetorian-inc/trajan/pkg/azuredevops"
)

func TestAuthorizeVariableGroups(t *testing.T) {
	t.Run("empty groups list", func(t *testing.T) {
		// Test that empty groups list doesn't panic
		ctx := context.Background()

		// Using nil client since we won't actually make API calls
		err := AuthorizeVariableGroups(ctx, nil, "test-project", 123, []azuredevops.VariableGroup{})

		// Should succeed with no groups to authorize
		assert.NoError(t, err)
	})

	t.Run("nil groups list", func(t *testing.T) {
		// Test that nil groups list doesn't panic
		ctx := context.Background()

		err := AuthorizeVariableGroups(ctx, nil, "test-project", 123, nil)

		// Should succeed with nil groups
		assert.NoError(t, err)
	})
}
