package graph

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNode_AddTag_NilMap(t *testing.T) {
	node := &BaseNode{
		id:       "test",
		nodeType: NodeTypeWorkflow,
		tags:     nil,
	}

	node.AddTag(TagPush)

	assert.True(t, node.HasTag(TagPush))
}
