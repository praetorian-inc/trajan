// Package attackpayloads is the single embedding point for the job-template
// corpus, mirroring the detection-rule corpus. A fragment is data: an id, a
// flavor, a typed parameter schema and a body rendered with << >> delimiters so
// a CI platform's own ${{ }} expressions pass through verbatim.
package attackpayloads

import "embed"

//go:embed all:github
var FS embed.FS
