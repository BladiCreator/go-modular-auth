// Package plugins exposes capability aliases for GoModularAuth plugins.
package plugins

import (
	deviceauth "github.com/BladiCreator/go-modular-auth/plugins/device-authorization"
)

// DeviceAuthorization is the strongly typed capability provided by the device-authorization module.
type DeviceAuthorization = deviceauth.DeviceAuthorization
