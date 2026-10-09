// Package plugins exposes capability aliases for GoModularAuth plugins.
package plugins

import (
	oidc "github.com/BladiCreator/go-modular-auth-oidc"
)

// OIDC is the strongly typed capability provided by the oidc module.
type OIDC = oidc.OIDC
