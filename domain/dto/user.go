// Package dto provides Data Transfer Objects (Params) for authentication operations.
package dto

type (
	// SignUpParams defines the data payload for user registration.
	SignUpParams struct {
		Name     string         `json:"name" binding:"required"`
		Email    string         `json:"email" binding:"required,email"`
		Password string         `json:"password" binding:"required,min=6"`
		Extra    map[string]any `json:"extra,omitempty"`
	}

	// SignInParams defines the credentials payload for authentication.
	SignInParams struct {
		Email    string         `json:"email" binding:"required,email"`
		Password string         `json:"password" binding:"required,min=6"`
		Extra    map[string]any `json:"extra,omitempty"`
	}

	// UpdateUserParams defines the data payload for updating user details.
	UpdateUserParams struct {
		Name  string         `json:"name" binding:"required"`
		Email string         `json:"email" binding:"required,email"`
		Extra map[string]any `json:"extra,omitempty"`
	}

	// ChangePasswordParams defines the payload for password change requests.
	ChangePasswordParams struct {
		UserID          string         `json:"userId"`
		CurrentPassword string         `json:"currentPassword" binding:"required"`
		NewPassword     string         `json:"newPassword" binding:"required,min=6"`
		Extra           map[string]any `json:"extra,omitempty"`
	}

	// SendVerificationEmailParams defines the payload for requesting an email verification link or token.
	SendVerificationEmailParams struct {
		Email string         `json:"email" binding:"required,email"`
		Extra map[string]any `json:"extra,omitempty"`
	}

	// VerifyEmailParams defines the token payload for email verification.
	VerifyEmailParams struct {
		Token string         `json:"token" binding:"required"`
		Extra map[string]any `json:"extra,omitempty"`
	}

	// VerifyPasswordParams defines the payload for checking if the provided password matches the user's current password.
	VerifyPasswordParams struct {
		UserID   string         `json:"userId" binding:"required"`
		Password string         `json:"password" binding:"required"`
		Extra    map[string]any `json:"extra,omitempty"`
	}

	// ForgotPasswordParams defines the payload for requesting a password reset email.
	ForgotPasswordParams struct {
		Email string         `json:"email" binding:"required,email"`
		Extra map[string]any `json:"extra,omitempty"`
	}

	// ResetPasswordParams defines the payload for setting a new password using a reset token.
	ResetPasswordParams struct {
		Token       string         `json:"token" binding:"required"`
		NewPassword string         `json:"newPassword" binding:"required,min=6"`
		Extra       map[string]any `json:"extra,omitempty"`
	}

	// CreateUserParams defines the mutable parameter payload passed to repository user creation operations.
	CreateUserParams struct {
		Email        string         `json:"email"`
		PasswordHash string         `json:"-"`
		Name         string         `json:"name"`
		Role         string         `json:"role,omitempty"`
		Extra        map[string]any `json:"extra,omitempty"`
	}
)

// Set safely attaches dynamic metadata to SignUpParams.
func (p *SignUpParams) Set(key string, value any) {
	if p.Extra == nil {
		p.Extra = make(map[string]any)
	}
	p.Extra[key] = value
}

// Get safely retrieves dynamic metadata from SignUpParams.
func (p *SignUpParams) Get(key string) (any, bool) {
	if p.Extra == nil {
		return nil, false
	}
	val, ok := p.Extra[key]
	return val, ok
}

// Set safely attaches dynamic metadata to SignInParams.
func (p *SignInParams) Set(key string, value any) {
	if p.Extra == nil {
		p.Extra = make(map[string]any)
	}
	p.Extra[key] = value
}

// Get safely retrieves dynamic metadata from SignInParams.
func (p *SignInParams) Get(key string) (any, bool) {
	if p.Extra == nil {
		return nil, false
	}
	val, ok := p.Extra[key]
	return val, ok
}

// Set safely attaches dynamic metadata to ChangePasswordParams.
func (p *ChangePasswordParams) Set(key string, value any) {
	if p.Extra == nil {
		p.Extra = make(map[string]any)
	}
	p.Extra[key] = value
}

// Get safely retrieves dynamic metadata from ChangePasswordParams.
func (p *ChangePasswordParams) Get(key string) (any, bool) {
	if p.Extra == nil {
		return nil, false
	}
	val, ok := p.Extra[key]
	return val, ok
}

// Set safely attaches dynamic metadata to ForgotPasswordParams.
func (p *ForgotPasswordParams) Set(key string, value any) {
	if p.Extra == nil {
		p.Extra = make(map[string]any)
	}
	p.Extra[key] = value
}

// Get safely retrieves dynamic metadata from ForgotPasswordParams.
func (p *ForgotPasswordParams) Get(key string) (any, bool) {
	if p.Extra == nil {
		return nil, false
	}
	val, ok := p.Extra[key]
	return val, ok
}

// Set safely attaches dynamic metadata to ResetPasswordParams.
func (p *ResetPasswordParams) Set(key string, value any) {
	if p.Extra == nil {
		p.Extra = make(map[string]any)
	}
	p.Extra[key] = value
}

// Get safely retrieves dynamic metadata from ResetPasswordParams.
func (p *ResetPasswordParams) Get(key string) (any, bool) {
	if p.Extra == nil {
		return nil, false
	}
	val, ok := p.Extra[key]
	return val, ok
}

// Set safely attaches dynamic metadata to SendVerificationEmailParams.
func (p *SendVerificationEmailParams) Set(key string, value any) {
	if p.Extra == nil {
		p.Extra = make(map[string]any)
	}
	p.Extra[key] = value
}

// Get safely retrieves dynamic metadata from SendVerificationEmailParams.
func (p *SendVerificationEmailParams) Get(key string) (any, bool) {
	if p.Extra == nil {
		return nil, false
	}
	val, ok := p.Extra[key]
	return val, ok
}

// Set safely attaches dynamic metadata to VerifyEmailParams.
func (p *VerifyEmailParams) Set(key string, value any) {
	if p.Extra == nil {
		p.Extra = make(map[string]any)
	}
	p.Extra[key] = value
}

// Get safely retrieves dynamic metadata from VerifyEmailParams.
func (p *VerifyEmailParams) Get(key string) (any, bool) {
	if p.Extra == nil {
		return nil, false
	}
	val, ok := p.Extra[key]
	return val, ok
}

// Set safely attaches dynamic metadata to VerifyPasswordParams.
func (p *VerifyPasswordParams) Set(key string, value any) {
	if p.Extra == nil {
		p.Extra = make(map[string]any)
	}
	p.Extra[key] = value
}

// Get safely retrieves dynamic metadata from VerifyPasswordParams.
func (p *VerifyPasswordParams) Get(key string) (any, bool) {
	if p.Extra == nil {
		return nil, false
	}
	val, ok := p.Extra[key]
	return val, ok
}

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
