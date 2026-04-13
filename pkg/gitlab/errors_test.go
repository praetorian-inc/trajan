package gitlab

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAPIError_Error(t *testing.T) {
	err := &APIError{StatusCode: 404, Body: `{"message":"not found"}`}
	assert.Equal(t, `API error 404: {"message":"not found"}`, err.Error())
}

func TestAPIError_ErrorsAs_ThroughWrapping(t *testing.T) {
	original := &APIError{StatusCode: 403, Body: "Forbidden"}
	wrapped := fmt.Errorf("listing variables: %w", original)

	var apiErr *APIError
	require.True(t, errors.As(wrapped, &apiErr))
	assert.Equal(t, 403, apiErr.StatusCode)
	assert.Equal(t, "Forbidden", apiErr.Body)
}

func TestIsPermissionError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{"nil", nil, false},
		{"non-API error", errors.New("something else"), false},
		{"403 direct", &APIError{StatusCode: 403, Body: "Forbidden"}, true},
		{"404 direct", &APIError{StatusCode: 404, Body: "Not Found"}, false},
		{"403 wrapped once", fmt.Errorf("listing group vars: %w", &APIError{StatusCode: 403}), true},
		{"403 wrapped twice", fmt.Errorf("outer: %w", fmt.Errorf("inner: %w", &APIError{StatusCode: 403})), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, IsPermissionError(tt.err))
		})
	}
}

func TestIsNotFoundError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{"nil", nil, false},
		{"non-API error", errors.New("something else"), false},
		{"404 direct", &APIError{StatusCode: 404, Body: "Not Found"}, true},
		{"403 direct", &APIError{StatusCode: 403, Body: "Forbidden"}, false},
		{"404 wrapped", fmt.Errorf("getting workflow file: %w", &APIError{StatusCode: 404}), true},
		{"404 wrapped twice", fmt.Errorf("outer: %w", fmt.Errorf("inner: %w", &APIError{StatusCode: 404})), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, IsNotFoundError(tt.err))
		})
	}
}

func TestIsGoneError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{"nil", nil, false},
		{"non-API error", errors.New("something else"), false},
		{"410 direct", &APIError{StatusCode: 410, Body: "Gone"}, true},
		{"404 direct", &APIError{StatusCode: 404, Body: "Not Found"}, false},
		{"410 wrapped", fmt.Errorf("getting job trace: %w", &APIError{StatusCode: 410}), true},
		{"410 wrapped twice", fmt.Errorf("outer: %w", fmt.Errorf("inner: %w", &APIError{StatusCode: 410})), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, IsGoneError(tt.err))
		})
	}
}
