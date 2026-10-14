// Package plugins exposes the capability aliases for GoModularAuth plugins.
package plugins

import (
	"github.com/BladiCreator/go-modular-auth/plugins/magic-link"
)

// MagicLink is the strongly typed capability provided by the magiclink module.
type MagicLink = magiclink.MagicLink
