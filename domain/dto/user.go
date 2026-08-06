// Package dto provides Data Transfer Objects for authentication operations.
package dto

type (
	// SignUp defines the data payload for user registration.
	SignUp struct {
		Name     string `json:"name" binding:"required"`
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required,min=6"`
	}

	// SignUpDTO is an alias for SignUp.
	SignUpDTO = SignUp

	// SignIn defines the credentials payload for authentication.
	SignIn struct {
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required,min=6"`
	}

	// SignInDTO is an alias for SignIn.
	SignInDTO = SignIn

	// UpdateUser defines the data payload for updating user details.
	UpdateUser struct {
		Name  string `json:"name" binding:"required"`
		Email string `json:"email" binding:"required,email"`
	}

	// ChangePassword defines the payload for password change requests.
	ChangePassword struct {
		UserID          string `json:"userId"`
		CurrentPassword string `json:"currentPassword" binding:"required"`
		NewPassword     string `json:"newPassword" binding:"required,min=6"`
	}

	// ChangePasswordDTO is an alias for ChangePassword.
	ChangePasswordDTO = ChangePassword

	// VerifyEmail defines the token payload for email verification.
	VerifyEmail struct {
		Token string `json:"token" binding:"required"`
	}

	// ForgotPassword defines the payload for requesting a password reset email.
	ForgotPassword struct {
		Email string `json:"email" binding:"required,email"`
	}

	// ForgotPasswordDTO is an alias for ForgotPassword.
	ForgotPasswordDTO = ForgotPassword

	// ResetPassword defines the payload for setting a new password using a reset token.
	ResetPassword struct {
		Token       string `json:"token" binding:"required"`
		NewPassword string `json:"newPassword" binding:"required,min=6"`
	}

	// ResetPasswordDTO is an alias for ResetPassword.
	ResetPasswordDTO = ResetPassword
)
