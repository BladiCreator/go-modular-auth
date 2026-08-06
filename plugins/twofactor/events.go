package twofactor

// Event names published by the TwoFactor plugin.
const (
	// EventTOTPGenerated is published when a new 2FA TOTP secret has been generated and stored.
	//
	// Event payload: (ctx context.Context, userID string, secret string)
	//
	// Example usage:
	//
	//	app.Events().Subscribe(twofactor.EventTOTPGenerated, func(ctx context.Context, userID string, secret string) {
	//		log.Printf("New 2FA TOTP secret generated for user %s: %s", userID, secret)
	//	})
	EventTOTPGenerated = "two-factor:totp:generated"
)
