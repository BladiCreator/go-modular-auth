// Package plugins exposes the capability aliases for GoModularAuth plugins.
package plugins

import (
	multisession "github.com/BladiCreator/go-modular-auth/plugins/multisession"
)

// MultiSession is the strongly typed capability provided by the multisession module.
type MultiSession = multisession.MultiSession
