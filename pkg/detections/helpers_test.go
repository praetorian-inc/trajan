package detections

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBuildChainFromNodes_Empty(t *testing.T) {
	chain := BuildChainFromNodes()
	assert.Nil(t, chain)
}
