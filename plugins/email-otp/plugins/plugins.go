// Package plugins exposes the capability aliases for GoModularAuth plugins.
package plugins

import (
	emailotp "github.com/BladiCreator/go-modular-auth-email-otp"
)

// EmailOTP is the strongly typed capability provided by the email-otp module.
type EmailOTP = emailotp.EmailOTP
