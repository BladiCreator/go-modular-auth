package captcha

import (
	"time"
)

// PluginID is the unique string identifier for the Captcha plugin ("captcha").
const PluginID = "captcha"

// HeaderCaptchaResponse is the standard HTTP header used by client applications to submit the captcha token.
const HeaderCaptchaResponse = "x-captcha-response"

// DefaultVerifyTimeout specifies the maximum duration allowed for outgoing verification requests.
const DefaultVerifyTimeout = 10 * time.Second

// DefaultMinScore defines the default minimum passing score for Google reCAPTCHA v3.
const DefaultMinScore = 0.5

// DefaultEndpoints lists the default authentication endpoints protected by captcha verification.
var DefaultEndpoints = []string{
	"/sign-up/email",
	"/sign-in/email",
	"/request-password-reset",
}

// DefaultExemptEndpoints lists endpoints that are exempted from captcha verification.
var DefaultExemptEndpoints = []string{
	"/sign-in/email-otp",
}

// DefaultSiteVerifyURLs maps each captcha provider to its official verification endpoint URL.
var DefaultSiteVerifyURLs = map[Provider]string{
	ProviderCloudflareTurnstile: "https://challenges.cloudflare.com/turnstile/v0/siteverify",
	ProviderGoogleRecaptcha:     "https://www.google.com/recaptcha/api/siteverify",
	ProviderHCaptcha:            "https://api.hcaptcha.com/siteverify",
	ProviderCaptchaFox:          "https://api.captchafox.com/siteverify",
}
