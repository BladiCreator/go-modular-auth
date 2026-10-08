// Package plugins exposes capability aliases for GoModularAuth plugins.
package plugins

import (
	apikeys "github.com/BladiCreator/go-modular-auth-apikeys"
)

// APIKeys is the strongly typed capability provided by the apikeys module.
type APIKeys = apikeys.APIKeys
