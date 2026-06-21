package gitlab

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewClient_AppendsAPIv4(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"http://localhost:8000", "http://localhost:8000/api/v4"},
		{"http://localhost:8000/", "http://localhost:8000/api/v4"},
		{"http://localhost:8000/api/v4", "http://localhost:8000/api/v4"},
		{"https://gitlab.example.com", "https://gitlab.example.com/api/v4"},
		{"", "https://gitlab.com/api/v4"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			client := NewClient(tt.input, "test-token")
			// Access private field via String() method
			assert.Contains(t, client.String(), tt.expected)
		})
	}
}
