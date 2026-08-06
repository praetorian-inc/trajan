// Package shared provides cross-platform detection logic
package shared

import (
	"github.com/praetorian-inc/trajan/pkg/detections"
)

type SecretDetector interface {
	DetectSecretPattern(value string) []SecretMatch
}

type SecretMatch struct {
	Pattern    string
	Confidence detections.Confidence
	Location   string
}
