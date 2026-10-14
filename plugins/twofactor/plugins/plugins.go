// Package plugins exposes the capability aliases for GoModularAuth plugins.
package plugins

import (
	twofactor "github.com/BladiCreator/go-modular-auth/plugins/twofactor"
)

// TwoFactor is the strongly typed capability provided by the twofactor module.
type TwoFactor = twofactor.TwoFactor
