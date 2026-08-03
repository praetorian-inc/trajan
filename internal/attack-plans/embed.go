// Package attackplans is the single embedding point for the canonical attack
// chain templates, mirroring the detection-rule corpus. A plan template is data:
// flat YAML validated against the live registry by a CI test.
package attackplans

import "embed"

//go:embed all:github
var FS embed.FS
