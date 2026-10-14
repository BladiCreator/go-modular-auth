// Package plugins exposes capability aliases for GoModularAuth plugins.
package plugins

import (
	"github.com/BladiCreator/go-modular-auth/plugins/admin"
)

// Admin is the strongly typed capability provided by the admin module.
type Admin = admin.Admin
