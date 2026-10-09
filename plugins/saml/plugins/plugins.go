// Package plugins exposes capability aliases for GoModularAuth plugins.
package plugins

import (
	saml "github.com/BladiCreator/go-modular-auth-saml"
)

// SAML is the strongly typed capability provided by the saml module.
type SAML = saml.SAML
