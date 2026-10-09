// Package plugins exposes capability aliases for GoModularAuth plugins.
package plugins

import (
	ratelimit "github.com/BladiCreator/go-modular-auth-rate-limit"
)

// RateLimit is the strongly typed capability provided by the rate-limit module.
type RateLimit = ratelimit.RateLimit
