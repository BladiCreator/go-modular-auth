package passkey

// Metadata keys for extra context passed in parameters or event payloads.
const (
	ExtraKeyOrigin         = "origin"
	ExtraKeyAAGUID         = "aaguid"
	ExtraKeyDeviceType     = "deviceType"
	ExtraKeyTransports     = "transports"
	ExtraKeyChallengeToken = "challengeToken"
	ExtraKeyUserAgent      = "userAgent"
	ExtraKeyIPAddress      = "ipAddress"
)

// Shared context storage keys for plugin.Context.
const (
	StoreKeyRPID        = "passkey:rp_id"
	StoreKeyRPOrigins   = "passkey:rp_origins"
	StoreKeyRPName      = "passkey:rp_name"
	StoreKeyActiveCount = "passkey:active_count"
)
