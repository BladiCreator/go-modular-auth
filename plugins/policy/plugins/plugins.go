// Package plugins exposes capability aliases for GoModularAuth plugins.
package plugins

import (
	policy "github.com/BladiCreator/go-modular-auth-policy"
)

// Policy is the strongly typed capability provided by the gomodularauth-policy module.
type Policy = policy.Policy
