package secrets

import (
	"regexp"

	"github.com/praetorian-inc/trajan/pkg/detections"
	"github.com/praetorian-inc/trajan/pkg/detections/shared"
)

type Detector struct {
	patterns []secretPattern
}

type secretPattern struct {
	name       string
	regex      *regexp.Regexp
	confidence detections.Confidence
}

func New() *Detector {
	return &Detector{
		patterns: []secretPattern{
			{
				name:       "AWS Access Key",
				regex:      regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
				confidence: detections.ConfidenceHigh,
			},
			{
				name:       "AWS Secret Key",
				regex:      regexp.MustCompile(`[0-9a-zA-Z/+]{40}`),
				confidence: detections.ConfidenceMedium, // High false positive rate
			},
			{
				name:       "GitHub Personal Access Token",
				regex:      regexp.MustCompile(`ghp_[a-zA-Z0-9]{36}`),
				confidence: detections.ConfidenceHigh,
			},
			{
				name:       "GitHub OAuth Token",
				regex:      regexp.MustCompile(`gho_[a-zA-Z0-9]{36}`),
				confidence: detections.ConfidenceHigh,
			},
			{
				name:       "GitLab Personal Access Token",
				regex:      regexp.MustCompile(`glpat-[a-zA-Z0-9_-]{20}`),
				confidence: detections.ConfidenceHigh,
			},
			{
				name:       "Generic API Key",
				regex:      regexp.MustCompile(`(?i)(api[_-]?key|apikey|secret[_-]?key)\s*[:=]\s*['"]?[a-zA-Z0-9_-]{20,}`),
				confidence: detections.ConfidenceMedium,
			},
			{
				name:       "Private Key Header",
				regex:      regexp.MustCompile(`-----BEGIN (RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----`),
				confidence: detections.ConfidenceHigh,
			},
			{
				name:       "JWT Token",
				regex:      regexp.MustCompile(`eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*`),
				confidence: detections.ConfidenceHigh,
			},
		},
	}
}

func (d *Detector) DetectSecretPattern(value string) []shared.SecretMatch {
	var matches []shared.SecretMatch

	for _, pattern := range d.patterns {
		if locs := pattern.regex.FindStringIndex(value); locs != nil {
			matches = append(matches, shared.SecretMatch{
				Pattern:    pattern.name,
				Confidence: pattern.confidence,
				Location:   value[locs[0]:locs[1]],
			})
		}
	}

	return matches
}

var _ shared.SecretDetector = (*Detector)(nil)
