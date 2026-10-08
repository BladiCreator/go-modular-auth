// Package plugins exposes strongly-typed capability aliases for GoModularAuth plugins.
package plugins

import (
	oauth "github.com/BladiCreator/go-modular-auth-oauth"
)

// OAuth is the strongly typed capability provided by the oauth module.
type OAuth = oauth.OAuth
