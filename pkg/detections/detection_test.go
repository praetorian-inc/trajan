package detections

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/trajan/pkg/analysis/graph"
)

type mockDetection struct {
	name string
}

func (m *mockDetection) Name() string       { return m.name }
func (m *mockDetection) Platform() string   { return "github" }
func (m *mockDetection) Severity() Severity { return SeverityHigh }
func (m *mockDetection) Detect(ctx context.Context, g *graph.Graph) ([]Finding, error) {
	return nil, nil
}

type mockAPIDetection struct {
	mockDetection
}

func (m *mockAPIDetection) RequiresAPI() bool { return true }

func TestRequiresAPI_FalseByDefault(t *testing.T) {
	d := &mockDetection{name: "test"}
	assert.False(t, RequiresAPI(d))
}

func TestRequiresAPI_TrueWhenImplemented(t *testing.T) {
	d := &mockAPIDetection{mockDetection: mockDetection{name: "api-test"}}
	assert.True(t, RequiresAPI(d))
}

func TestPartitionByAPIRequirement(t *testing.T) {
	local1 := &mockDetection{name: "local1"}
	local2 := &mockDetection{name: "local2"}
	api1 := &mockAPIDetection{mockDetection: mockDetection{name: "api1"}}

	all := []Detection{local1, api1, local2}

	localRunnable, apiOnly := PartitionByAPIRequirement(all)

	require.Len(t, localRunnable, 2)
	require.Len(t, apiOnly, 1)

	// Order within each slice must be preserved
	assert.Equal(t, "local1", localRunnable[0].Name())
	assert.Equal(t, "local2", localRunnable[1].Name())
	assert.Equal(t, "api1", apiOnly[0].Name())
}
