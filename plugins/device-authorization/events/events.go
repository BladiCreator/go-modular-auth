// Package events re-exports device authorization audit event identifiers and payload types.
package events

import (
	deviceauth "github.com/BladiCreator/go-modular-auth-device-authorization"
)

const (
	EventDeviceAuthStarted    = deviceauth.EventDeviceAuthStarted
	EventDeviceAuthAuthorized = deviceauth.EventDeviceAuthAuthorized
	EventDeviceAuthDenied     = deviceauth.EventDeviceAuthDenied
	EventDeviceAuthConsumed   = deviceauth.EventDeviceAuthConsumed
)

type DeviceAuthStartedPayload = deviceauth.DeviceAuthStartedPayload
type DeviceAuthAuthorizedPayload = deviceauth.DeviceAuthAuthorizedPayload
type DeviceAuthDeniedPayload = deviceauth.DeviceAuthDeniedPayload
type DeviceAuthConsumedPayload = deviceauth.DeviceAuthConsumedPayload
