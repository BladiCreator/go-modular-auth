package emailpassword_test

import (
	"context"
	"testing"
	"time"

	"github.com/BladiCreator/go-modular-auth/auth"
	"github.com/BladiCreator/go-modular-auth/config"
	"github.com/BladiCreator/go-modular-auth/domain/dto"
	"github.com/BladiCreator/go-modular-auth/internal/mock"
	"github.com/BladiCreator/go-modular-auth/plugins"
	"github.com/BladiCreator/go-modular-auth/plugins/emailpassword"
)

func setupTestAuth(t *testing.T, opts ...emailpassword.Option) (*auth.Auth, *emailpassword.Plugin, *mock.MockRepo) {
	t.Helper()
	repo := mock.NewMockRepo()

	app, err := auth.New(
		config.WithPlugins(
			plugins.EmailPassword(repo, opts...),
		),
	)
	if err != nil {
		t.Fatalf("Failed to initialize auth: %v", err)
	}

	p := auth.Plugin[emailpassword.Plugin](app)
	return app, p, repo
}

func TestSignUp(t *testing.T) {
	_, p, _ := setupTestAuth(t, emailpassword.WithMinPasswordLength(8))
	ctx := context.Background()

	// Short password
	_, err := p.SignUp(ctx, dto.SignUpDTO{
		Email:    "test@example.com",
		Password: "short",
		Name:     "Test User",
	})
	if err != emailpassword.ErrPasswordTooShort {
		t.Errorf("Expected ErrPasswordTooShort, got %v", err)
	}

	// Successful sign up
	user, err := p.SignUp(ctx, dto.SignUpDTO{
		Email:    "test@example.com",
		Password: "password123",
		Name:     "Test User",
	})
	if err != nil {
		t.Fatalf("SignUp failed: %v", err)
	}
	if user.Email != "test@example.com" {
		t.Errorf("Expected email test@example.com, got %s", user.Email)
	}

	// Duplicate sign up
	_, err = p.SignUp(ctx, dto.SignUpDTO{
		Email:    "test@example.com",
		Password: "password123",
		Name:     "Test User",
	})
	if err != emailpassword.ErrUserAlreadyExists {
		t.Errorf("Expected ErrUserAlreadyExists, got %v", err)
	}
}

func TestSignIn(t *testing.T) {
	_, p, repo := setupTestAuth(t, emailpassword.WithMinPasswordLength(8))
	ctx := context.Background()

	// Register user
	user, err := p.SignUp(ctx, dto.SignUpDTO{
		Email:    "signin@example.com",
		Password: "password123",
		Name:     "SignIn User",
	})
	if err != nil {
		t.Fatalf("SignUp failed: %v", err)
	}

	// Invalid password
	_, err = p.SignIn(ctx, dto.SignInDTO{
		Email:    "signin@example.com",
		Password: "wrongpassword",
	})
	if err != emailpassword.ErrInvalidCredentials {
		t.Errorf("Expected ErrInvalidCredentials, got %v", err)
	}

	// Invalid email
	_, err = p.SignIn(ctx, dto.SignInDTO{
		Email:    "nonexistent@example.com",
		Password: "password123",
	})
	if err != emailpassword.ErrInvalidCredentials {
		t.Errorf("Expected ErrInvalidCredentials, got %v", err)
	}

	// Successful sign in
	signedInUser, err := p.SignIn(ctx, dto.SignInDTO{
		Email:    "signin@example.com",
		Password: "password123",
	})
	if err != nil {
		t.Fatalf("SignIn failed: %v", err)
	}
	if signedInUser.ID != user.ID {
		t.Errorf("Expected user ID %s, got %s", user.ID, signedInUser.ID)
	}

	// Email verification required scenario
	_, pVerify, _ := setupTestAuth(t, emailpassword.WithRequireEmailVerification(true))
	unverifiedUser, err := pVerify.SignUp(ctx, dto.SignUpDTO{
		Email:    "unverified@example.com",
		Password: "password123",
		Name:     "Unverified User",
	})
	if err != nil {
		t.Fatalf("SignUp failed: %v", err)
	}

	_, err = pVerify.SignIn(ctx, dto.SignInDTO{
		Email:    "unverified@example.com",
		Password: "password123",
	})
	if err != emailpassword.ErrEmailNotVerified {
		t.Errorf("Expected ErrEmailNotVerified, got %v", err)
	}

	// Mark email verified and retry
	unverifiedUser.EmailVerified = true
	_ = repo.UpdateUser(ctx, unverifiedUser)

	_, err = pVerify.SignIn(ctx, dto.SignInDTO{
		Email:    "unverified@example.com",
		Password: "password123",
	})
	if err != nil {
		t.Errorf("Expected signin to succeed after email verification, got %v", err)
	}
}

func TestChangePassword(t *testing.T) {
	_, p, _ := setupTestAuth(t)
	ctx := context.Background()

	user, err := p.SignUp(ctx, dto.SignUpDTO{
		Email:    "changepass@example.com",
		Password: "oldPassword123",
		Name:     "ChangePass User",
	})
	if err != nil {
		t.Fatalf("SignUp failed: %v", err)
	}

	// Incorrect current password
	err = p.ChangePassword(ctx, dto.ChangePasswordDTO{
		UserID:          user.ID,
		CurrentPassword: "wrongPassword",
		NewPassword:     "newPassword123",
	})
	if err != emailpassword.ErrInvalidCurrentPass {
		t.Errorf("Expected ErrInvalidCurrentPass, got %v", err)
	}

	// Short new password
	err = p.ChangePassword(ctx, dto.ChangePasswordDTO{
		UserID:          user.ID,
		CurrentPassword: "oldPassword123",
		NewPassword:     "short",
	})
	if err != emailpassword.ErrPasswordTooShort {
		t.Errorf("Expected ErrPasswordTooShort, got %v", err)
	}

	// Successful password change
	err = p.ChangePassword(ctx, dto.ChangePasswordDTO{
		UserID:          user.ID,
		CurrentPassword: "oldPassword123",
		NewPassword:     "newPassword123",
	})
	if err != nil {
		t.Fatalf("ChangePassword failed: %v", err)
	}

	// Verify sign in with new password
	_, err = p.SignIn(ctx, dto.SignInDTO{
		Email:    "changepass@example.com",
		Password: "newPassword123",
	})
	if err != nil {
		t.Errorf("SignIn with new password failed: %v", err)
	}
}

func TestForgotPasswordAndResetPassword(t *testing.T) {
	_, p, _ := setupTestAuth(t, emailpassword.WithResetTokenExpiry(100*time.Millisecond))
	ctx := context.Background()

	// Forgot password for non-existent user
	_, err := p.ForgotPassword(ctx, dto.ForgotPasswordDTO{Email: "unknown@example.com"})
	if err != emailpassword.ErrUserNotFound {
		t.Errorf("Expected ErrUserNotFound, got %v", err)
	}

	// Register user
	_, err = p.SignUp(ctx, dto.SignUpDTO{
		Email:    "reset@example.com",
		Password: "originalPassword123",
		Name:     "Reset User",
	})
	if err != nil {
		t.Fatalf("SignUp failed: %v", err)
	}

	// Request forgot password
	tokenRecord, err := p.ForgotPassword(ctx, dto.ForgotPasswordDTO{Email: "reset@example.com"})
	if err != nil {
		t.Fatalf("ForgotPassword failed: %v", err)
	}
	if tokenRecord.Token == "" {
		t.Error("Expected non-empty token string")
	}

	// Reset password with invalid token
	err = p.ResetPassword(ctx, dto.ResetPasswordDTO{
		Token:       "invalid_token",
		NewPassword: "brandNewPassword123",
	})
	if err != emailpassword.ErrInvalidToken {
		t.Errorf("Expected ErrInvalidToken, got %v", err)
	}

	// Successful reset password
	err = p.ResetPassword(ctx, dto.ResetPasswordDTO{
		Token:       tokenRecord.Token,
		NewPassword: "brandNewPassword123",
	})
	if err != nil {
		t.Fatalf("ResetPassword failed: %v", err)
	}

	// Verify sign in with new password
	_, err = p.SignIn(ctx, dto.SignInDTO{
		Email:    "reset@example.com",
		Password: "brandNewPassword123",
	})
	if err != nil {
		t.Errorf("SignIn with reset password failed: %v", err)
	}

	// Test token expiry
	tokenRecordExpiry, err := p.ForgotPassword(ctx, dto.ForgotPasswordDTO{Email: "reset@example.com"})
	if err != nil {
		t.Fatalf("ForgotPassword failed: %v", err)
	}

	time.Sleep(150 * time.Millisecond)

	err = p.ResetPassword(ctx, dto.ResetPasswordDTO{
		Token:       tokenRecordExpiry.Token,
		NewPassword: "anotherPassword123",
	})
	if err != emailpassword.ErrTokenExpired {
		t.Errorf("Expected ErrTokenExpired, got %v", err)
	}
}

func TestEventEmissions(t *testing.T) {
	app, p, _ := setupTestAuth(t)
	ctx := context.Background()

	var signUpAfterEmitted, signInAfterEmitted, resetRequestedEmitted bool

	app.Events().Subscribe(emailpassword.EventSignUpAfter, func(ctx context.Context, payload any) {
		if req, ok := payload.(*emailpassword.SignUpEventPayload); ok && req.User != nil {
			signUpAfterEmitted = true
		}
	})

	app.Events().Subscribe(emailpassword.EventSignInAfter, func(ctx context.Context, payload any) {
		if req, ok := payload.(*emailpassword.SignInEventPayload); ok && req.User != nil {
			signInAfterEmitted = true
		}
	})

	app.Events().Subscribe(emailpassword.EventPasswordResetRequested, func(ctx context.Context, payload any) {
		if req, ok := payload.(*emailpassword.PasswordResetRequestedEventPayload); ok && req.Token != "" {
			resetRequestedEmitted = true
		}
	})

	_, err := p.SignUp(ctx, dto.SignUpDTO{
		Email:    "events@example.com",
		Password: "password123",
		Name:     "Events User",
	})
	if err != nil {
		t.Fatalf("SignUp failed: %v", err)
	}

	_, err = p.SignIn(ctx, dto.SignInDTO{
		Email:    "events@example.com",
		Password: "password123",
	})
	if err != nil {
		t.Fatalf("SignIn failed: %v", err)
	}

	_, err = p.ForgotPassword(ctx, dto.ForgotPasswordDTO{Email: "events@example.com"})
	if err != nil {
		t.Fatalf("ForgotPassword failed: %v", err)
	}

	if !signUpAfterEmitted {
		t.Error("Expected EventSignUpAfter to be emitted")
	}
	if !signInAfterEmitted {
		t.Error("Expected EventSignInAfter to be emitted")
	}
	if !resetRequestedEmitted {
		t.Error("Expected EventPasswordResetRequested to be emitted")
	}
}
