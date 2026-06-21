package analysis

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/praetorian-inc/trajan/pkg/analysis/graph"
)

func TestComputeJobTriggers_WorkflowLevel(t *testing.T) {
	yaml := `workflow:
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"

test:
  script:
    - echo test`

	g, _ := BuildGraph("test/repo", ".gitlab-ci.yml", []byte(yaml), nil)
	jobs := g.GetNodesByType(graph.NodeTypeJob)

	assert.Len(t, jobs, 1)
	job := jobs[0].(*graph.JobNode)
	assert.Contains(t, job.ComputedTriggers, "merge_request", "Job should inherit workflow trigger")
}

func TestComputeJobTriggers_JobLevel(t *testing.T) {
	yaml := `test:
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  script:
    - echo test`

	g, _ := BuildGraph("test/repo", ".gitlab-ci.yml", []byte(yaml), nil)
	jobs := g.GetNodesByType(graph.NodeTypeJob)

	assert.Len(t, jobs, 1)
	job := jobs[0].(*graph.JobNode)
	assert.Contains(t, job.ComputedTriggers, "merge_request", "Job should extract trigger from job-level rules")
}
