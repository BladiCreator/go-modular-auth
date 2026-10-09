// Package plugins exposes capability aliases for GoModularAuth plugins.
package plugins

import (
	"github.com/BladiCreator/go-modular-auth-organizations"
)

// Organization is the strongly typed capability provided by the organizations module.
type Organization = organizations.Organization
