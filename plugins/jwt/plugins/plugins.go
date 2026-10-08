// Package plugins exposes capability aliases for GoModularAuth plugins.
package plugins

import (
	jwt "github.com/BladiCreator/go-modular-auth-jwt"
)

// JWT is the strongly typed capability provided by the jwt module.
type JWT = jwt.JWT
