// Package dto provides Data Transfer Objects (Params) for authentication operations.
package dto

type (
	// SignUpParams defines the data payload for user registration.
	SignUpParams struct {
		Name     string `json:"name" binding:"required"`
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required,min=6"`
	}

	// SignInParams defines the credentials payload for authentication.
	SignInParams struct {
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required,min=6"`
	}

	// UpdateUserParams defines the data payload for updating user details.
	UpdateUserParams struct {
		Name  string `json:"name" binding:"required"`
		Email string `json:"email" binding:"required,email"`
	}

	// ChangePasswordParams defines the payload for password change requests.
	ChangePasswordParams struct {
		UserID          string `json:"userId"`
		CurrentPassword string `json:"currentPassword" binding:"required"`
		NewPassword     string `json:"newPassword" binding:"required,min=6"`
	}

	// VerifyEmailParams defines the token payload for email verification.
	VerifyEmailParams struct {
		Token string `json:"token" binding:"required"`
	}

	// ForgotPasswordParams defines the payload for requesting a password reset email.
	ForgotPasswordParams struct {
		Email string `json:"email" binding:"required,email"`
	}

	// ResetPasswordParams defines the payload for setting a new password using a reset token.
	ResetPasswordParams struct {
		Token       string `json:"token" binding:"required"`
		NewPassword string `json:"newPassword" binding:"required,min=6"`
	}

	// CreateUserParams defines the mutable parameter payload passed to repository user creation operations.
	CreateUserParams struct {
		Email        string         `json:"email"`
		PasswordHash string         `json:"-"`
		Name         string         `json:"name"`
		Extra        map[string]any `json:"extra,omitempty"`
	}
)

// Set allows plugins or handlers to safely attach dynamic metadata.
func (p *CreateUserParams) Set(key string, value any) {
	if p.Extra == nil {
		p.Extra = make(map[string]any)
	}
	p.Extra[key] = value
}

// Get safely retrieves dynamic metadata by key.
func (p *CreateUserParams) Get(key string) (any, bool) {
	if p.Extra == nil {
		return nil, false
	}
	val, ok := p.Extra[key]
	return val, ok
}
