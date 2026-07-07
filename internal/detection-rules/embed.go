// Package detectionrules is the single embedding point for trajan's detection
// rule corpus. Each supported platform's rules live in a subdirectory named for
// the platform (github, gitlab, ado, jenkins); a platform package loads its own
// rules by walking the matching subtree of FS. The all: prefix keeps the empty
// platform stubs (.keep) embeddable so the patterns stay valid before rules land.
package detectionrules

import "embed"

//go:embed all:github all:gitlab all:ado all:jenkins
var FS embed.FS
