// Package plugins exposes capability aliases for GoModularAuth plugins.
package plugins

import (
	rbac "github.com/BladiCreator/go-modular-auth/plugins/rbac"
)

// RBAC is the strongly typed capability provided by the gomodularauth-rbac module.
type RBAC = rbac.RBAC
