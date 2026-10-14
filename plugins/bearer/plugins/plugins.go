// Package plugins exposes capability aliases for GoModularAuth plugins.
package plugins

import (
	"github.com/BladiCreator/go-modular-auth/plugins/bearer"
)

// Bearer is the strongly typed capability provided by the bearer module.
type Bearer = bearer.Bearer
