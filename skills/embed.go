// Package skills contains the downloadable agent skills bundled with tunn.
package skills

import _ "embed"

// Tunn is the canonical skill, also served at /agents/skill/SKILL.md.
//
//go:embed tunn/SKILL.md
var Tunn string
