// Package plugins exposes capability aliases for GoModularAuth plugins.
package plugins

import (
	"github.com/BladiCreator/go-modular-auth-anonymous"
)

// Anonymous is the strongly typed capability provided by the anonymous module.
type Anonymous = anonymous.Anonymous
