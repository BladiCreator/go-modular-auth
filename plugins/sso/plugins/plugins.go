// Package plugins exposes capability aliases for GoModularAuth plugins.
package plugins

import (
	sso "github.com/BladiCreator/go-modular-auth/plugins/sso"
)

// SSO is the strongly typed capability provided by the sso module.
type SSO = sso.SSO
