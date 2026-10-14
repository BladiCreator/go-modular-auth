// Package plugins exposes capability aliases for GoModularAuth plugins.
package plugins

import (
	audit "github.com/BladiCreator/go-modular-auth/plugins/audit"
)

// Audit is the strongly typed capability provided by the audit module.
type Audit = audit.Audit
