package inspection

import _ "embed"

// ReplayValidationJS is the shared, local-only reconstruction check for both
// inspector forms. Reconstruct remains authoritative on the server.
//
//go:embed replay_validation.js
var ReplayValidationJS string
