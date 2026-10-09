package deviceauth

import (
	"context"
)

// DeviceAuthorization defines the RFC 8628 OAuth 2.0 Device Authorization Grant capability.
// Applications access it via auth.Get[plugins.DeviceAuthorization](a) or auth.Get[deviceauth.DeviceAuthorization](a).
type DeviceAuthorization interface {
	// Start initiates the device flow and returns device and user codes.
	Start(ctx context.Context, in DeviceAuthorizationRequestInput) (*DeviceAuthorizationResponse, error)

	// Poll checks device authorization status and issues tokens upon user approval.
	Poll(ctx context.Context, in PollInput) (*PollResponse, error)

	// VerifyUserCode inspects a user code submitted by the user on the verification page.
	VerifyUserCode(ctx context.Context, in VerifyUserCodeInput) (*UserCodeVerificationResult, error)

	// Authorize records user consent and associates the grant with the authorizing user.
	Authorize(ctx context.Context, in AuthorizeInput) error

	// Deny records user rejection of the authorization request.
	Deny(ctx context.Context, in DenyInput) error
}

// Capability is an alias for DeviceAuthorization to support standard capability discovery conventions.
type Capability = DeviceAuthorization
