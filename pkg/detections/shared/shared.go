// modules/trajan/pkg/detections/shared/shared.go
// Package shared provides cross-platform detection logic
package shared

import (
	"github.com/praetorian-inc/trajan/pkg/detections"
)

// SecretDetector detects potential secret exposure
type SecretDetector interface {
	// DetectSecretPattern checks if a string might expose secrets
	DetectSecretPattern(value string) []SecretMatch
}

// SecretMatch represents a detected secret pattern
type SecretMatch struct {
	Pattern    string
	Confidence detections.Confidence
	Location   string
}
