// Package detectionrules embeds the detection rule corpus, one subdirectory per
// platform; a platform package loads its own rules by walking that subtree of FS.
// The all: prefix keeps a platform whose only file is a .keep stub embeddable.
package detectionrules

import "embed"

//go:embed all:github all:gitlab all:ado all:jenkins
var FS embed.FS
