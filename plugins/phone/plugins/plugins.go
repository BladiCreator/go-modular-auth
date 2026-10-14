// Package plugins exposes strongly typed capability aliases for GoModularAuth plugins.
package plugins

import (
	phone "github.com/BladiCreator/go-modular-auth/plugins/phone"
)

// Phone is the strongly typed capability provided by the phone module.
type Phone = phone.Phone
