package parser

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGitLabParser_ExtractsLineNumbers(t *testing.T) {
	yaml := `workflow:
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"

test:
  script:
    - echo "test"

deploy:
  script:
    - echo "deploy"
`

	parser := NewGitLabParser()
	wf, err := parser.Parse([]byte(yaml))
	require.NoError(t, err)

	// Jobs should have line numbers
	assert.Greater(t, wf.Jobs["test"].Line, 0, "test job should have line number")
	assert.Greater(t, wf.Jobs["deploy"].Line, 0, "deploy job should have line number")

	// Steps should have line numbers
	assert.Greater(t, wf.Jobs["test"].Steps[0].Line, 0, "test step should have line number")
	assert.Greater(t, wf.Jobs["deploy"].Steps[0].Line, 0, "deploy step should have line number")
}
