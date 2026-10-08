// Package plugins exposes strongly-typed capability aliases for GoModularAuth plugins.
package plugins

import (
	passkey "github.com/BladiCreator/go-modular-auth-passkeys"
)

// Passkeys is the strongly typed capability provided by the passkey module.
type Passkeys = passkey.Passkeys

// Passkey is an alias for Passkeys.
type Passkey = passkey.Passkeys
