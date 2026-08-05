// pkg/analysis/graph/node_test.go
package graph

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNode_AddTag_NilMap(t *testing.T) {
	// Test the nil map initialization branch
	node := &BaseNode{
		id:       "test",
		nodeType: NodeTypeWorkflow,
		tags:     nil, // explicitly nil
	}

	// Should not panic, should initialize map
	node.AddTag(TagPush)

	assert.True(t, node.HasTag(TagPush))
}
