package emailpassword_test

import (
	"context"
	"sync"
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
	_, p, _ := setupTestAuth(t, emailpassword.WithMinPasswordLength(8), emailpassword.WithMaxPasswordLength(32))
	ctx := context.Background()

	// 1. Invalid email
	_, err := p.SignUp(ctx, dto.SignUpParams{
		Email:    "not-an-email",
		Password: "password123",
		Name:     "Test User",
	})
	if err != emailpassword.ErrInvalidEmail {
		t.Errorf("Expected ErrInvalidEmail, got %v", err)
	}

	// 2. Short password
	_, err = p.SignUp(ctx, dto.SignUpParams{
		Email:    "test@example.com",
		Password: "short",
		Name:     "Test User",
	})
	if err != emailpassword.ErrPasswordTooShort {
		t.Errorf("Expected ErrPasswordTooShort, got %v", err)
	}

	// 3. Password exceeding maximum length
	_, err = p.SignUp(ctx, dto.SignUpParams{
		Email:    "test@example.com",
		Password: "thispasswordiswaytoolongtofitinthespecifiedlimit1234567890",
		Name:     "Test User",
	})
	if err != emailpassword.ErrPasswordTooLong {
		t.Errorf("Expected ErrPasswordTooLong, got %v", err)
	}

	// 4. Successful sign up
	user, err := p.SignUp(ctx, dto.SignUpParams{
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

	// 5. Duplicate sign up
	_, err = p.SignUp(ctx, dto.SignUpParams{
		Email:    "test@example.com",
		Password: "password123",
		Name:     "Test User",
	})
	if err != emailpassword.ErrUserAlreadyExists {
		t.Errorf("Expected ErrUserAlreadyExists, got %v", err)
	}
}

func TestSignUp_WithSendVerificationOnSignUp(t *testing.T) {
	var callbackInvoked bool
	var capturedEmail, capturedToken string

	_, p, _ := setupTestAuth(t,
		emailpassword.WithSendVerificationOnSignUp(true),
		emailpassword.WithSendVerificationEmail(func(ctx context.Context, email string, token string, expiresAt time.Time, extra map[string]any) error {
			callbackInvoked = true
			capturedEmail = email
			capturedToken = token
			return nil
		}),
	)
	ctx := context.Background()

	user, err := p.SignUp(ctx, dto.SignUpParams{
		Email:    "autosend@example.com",
		Password: "password123",
		Name:     "Auto Send",
	})
	if err != nil {
		t.Fatalf("SignUp failed: %v", err)
	}

	if !callbackInvoked {
		t.Error("Expected SendVerificationEmail callback to be invoked on sign up")
	}
	if capturedEmail != "autosend@example.com" || capturedToken == "" {
		t.Errorf("Unexpected captured email or token: %s, %s", capturedEmail, capturedToken)
	}

	// Complete verification
	verifiedUser, err := p.VerifyEmail(ctx, dto.VerifyEmailParams{Token: capturedToken})
	if err != nil {
		t.Fatalf("VerifyEmail failed: %v", err)
	}
	if verifiedUser.ID != user.ID || !verifiedUser.EmailVerified {
		t.Errorf("Expected user email to be verified, got: %v", verifiedUser.EmailVerified)
	}
}

func TestSignIn(t *testing.T) {
	_, p, repo := setupTestAuth(t, emailpassword.WithMinPasswordLength(8))
	ctx := context.Background()

	// Register user
	user, err := p.SignUp(ctx, dto.SignUpParams{
		Email:    "signin@example.com",
		Password: "password123",
		Name:     "SignIn User",
	})
	if err != nil {
		t.Fatalf("SignUp failed: %v", err)
	}

	// 1. Invalid password
	_, err = p.SignIn(ctx, dto.SignInParams{
		Email:    "signin@example.com",
		Password: "wrongpassword",
	})
	if err != emailpassword.ErrInvalidCredentials {
		t.Errorf("Expected ErrInvalidCredentials, got %v", err)
	}

	// 2. Non-existent email (triggers constant-time fake hash)
	_, err = p.SignIn(ctx, dto.SignInParams{
		Email:    "nonexistent@example.com",
		Password: "password123",
	})
	if err != emailpassword.ErrInvalidCredentials {
		t.Errorf("Expected ErrInvalidCredentials, got %v", err)
	}

	// 3. Successful sign in
	signedInUser, err := p.SignIn(ctx, dto.SignInParams{
		Email:    "signin@example.com",
		Password: "password123",
	})
	if err != nil {
		t.Fatalf("SignIn failed: %v", err)
	}
	if signedInUser.ID != user.ID {
		t.Errorf("Expected user ID %s, got %s", user.ID, signedInUser.ID)
	}

	// 4. Email verification required scenario
	_, pVerify, _ := setupTestAuth(t, emailpassword.WithRequireEmailVerification(true))
	unverifiedUser, err := pVerify.SignUp(ctx, dto.SignUpParams{
		Email:    "unverified@example.com",
		Password: "password123",
		Name:     "Unverified User",
	})
	if err != nil {
		t.Fatalf("SignUp failed: %v", err)
	}

	_, err = pVerify.SignIn(ctx, dto.SignInParams{
		Email:    "unverified@example.com",
		Password: "password123",
	})
	if err != emailpassword.ErrEmailNotVerified {
		t.Errorf("Expected ErrEmailNotVerified, got %v", err)
	}

	// Mark email verified and retry
	unverifiedUser.EmailVerified = true
	_ = repo.UpdateUser(ctx, unverifiedUser)

	_, err = pVerify.SignIn(ctx, dto.SignInParams{
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

	user, err := p.SignUp(ctx, dto.SignUpParams{
		Email:    "changepass@example.com",
		Password: "oldPassword123",
		Name:     "ChangePass User",
	})
	if err != nil {
		t.Fatalf("SignUp failed: %v", err)
	}

	// 1. Missing user ID
	err = p.ChangePassword(ctx, dto.ChangePasswordParams{
		UserID:          "",
		CurrentPassword: "oldPassword123",
		NewPassword:     "newPassword123",
	})
	if err != emailpassword.ErrInvalidParameter {
		t.Errorf("Expected ErrInvalidParameter, got %v", err)
	}

	// 2. Incorrect current password
	err = p.ChangePassword(ctx, dto.ChangePasswordParams{
		UserID:          user.ID,
		CurrentPassword: "wrongPassword",
		NewPassword:     "newPassword123",
	})
	if err != emailpassword.ErrInvalidCurrentPass {
		t.Errorf("Expected ErrInvalidCurrentPass, got %v", err)
	}

	// 3. Short new password
	err = p.ChangePassword(ctx, dto.ChangePasswordParams{
		UserID:          user.ID,
		CurrentPassword: "oldPassword123",
		NewPassword:     "short",
	})
	if err != emailpassword.ErrPasswordTooShort {
		t.Errorf("Expected ErrPasswordTooShort, got %v", err)
	}

	// 4. Successful password change
	err = p.ChangePassword(ctx, dto.ChangePasswordParams{
		UserID:          user.ID,
		CurrentPassword: "oldPassword123",
		NewPassword:     "newPassword123",
	})
	if err != nil {
		t.Fatalf("ChangePassword failed: %v", err)
	}

	// 5. Verify sign in with new password
	_, err = p.SignIn(ctx, dto.SignInParams{
		Email:    "changepass@example.com",
		Password: "newPassword123",
	})
	if err != nil {
		t.Errorf("SignIn with new password failed: %v", err)
	}
}

func TestForgotPasswordAndResetPassword(t *testing.T) {
	var callbackFired bool
	var callbackToken string

	_, p, _ := setupTestAuth(t,
		emailpassword.WithResetTokenExpiry(100*time.Millisecond),
		emailpassword.WithSendResetPasswordEmail(func(ctx context.Context, email, token string, expiresAt time.Time, extra map[string]any) error {
			callbackFired = true
			callbackToken = token
			return nil
		}),
	)
	ctx := context.Background()

	// 1. Invalid email
	_, err := p.ForgotPassword(ctx, dto.ForgotPasswordParams{Email: "invalid-email"})
	if err != emailpassword.ErrInvalidEmail {
		t.Errorf("Expected ErrInvalidEmail, got %v", err)
	}

	// 2. Forgot password for non-existent user
	_, err = p.ForgotPassword(ctx, dto.ForgotPasswordParams{Email: "unknown@example.com"})
	if err != emailpassword.ErrUserNotFound {
		t.Errorf("Expected ErrUserNotFound, got %v", err)
	}

	// 3. Register user
	_, err = p.SignUp(ctx, dto.SignUpParams{
		Email:    "reset@example.com",
		Password: "originalPassword123",
		Name:     "Reset User",
	})
	if err != nil {
		t.Fatalf("SignUp failed: %v", err)
	}

	// 4. Request forgot password
	tokenRecord, err := p.ForgotPassword(ctx, dto.ForgotPasswordParams{Email: "reset@example.com"})
	if err != nil {
		t.Fatalf("ForgotPassword failed: %v", err)
	}
	if tokenRecord.Token == "" {
		t.Error("Expected non-empty token string")
	}
	if !callbackFired || callbackToken != tokenRecord.Token {
		t.Error("Expected SendResetPasswordEmail callback to be executed with token")
	}

	// 5. Reset password with empty token
	err = p.ResetPassword(ctx, dto.ResetPasswordParams{
		Token:       "",
		NewPassword: "brandNewPassword123",
	})
	if err != emailpassword.ErrInvalidParameter {
		t.Errorf("Expected ErrInvalidParameter, got %v", err)
	}

	// 6. Reset password with invalid token
	err = p.ResetPassword(ctx, dto.ResetPasswordParams{
		Token:       "invalid_token",
		NewPassword: "brandNewPassword123",
	})
	if err != emailpassword.ErrInvalidToken {
		t.Errorf("Expected ErrInvalidToken, got %v", err)
	}

	// 7. Successful reset password
	err = p.ResetPassword(ctx, dto.ResetPasswordParams{
		Token:       tokenRecord.Token,
		NewPassword: "brandNewPassword123",
	})
	if err != nil {
		t.Fatalf("ResetPassword failed: %v", err)
	}

	// 8. Single-use verification: retry with same token must fail
	err = p.ResetPassword(ctx, dto.ResetPasswordParams{
		Token:       tokenRecord.Token,
		NewPassword: "anotherPassword123",
	})
	if err != emailpassword.ErrInvalidToken {
		t.Errorf("Expected ErrInvalidToken when reusing consumed token, got %v", err)
	}

	// 9. Verify sign in with new password
	_, err = p.SignIn(ctx, dto.SignInParams{
		Email:    "reset@example.com",
		Password: "brandNewPassword123",
	})
	if err != nil {
		t.Errorf("SignIn with reset password failed: %v", err)
	}

	// 10. Test token expiry
	tokenRecordExpiry, err := p.ForgotPassword(ctx, dto.ForgotPasswordParams{Email: "reset@example.com"})
	if err != nil {
		t.Fatalf("ForgotPassword failed: %v", err)
	}

	time.Sleep(150 * time.Millisecond)

	err = p.ResetPassword(ctx, dto.ResetPasswordParams{
		Token:       tokenRecordExpiry.Token,
		NewPassword: "anotherPassword123",
	})
	if err != emailpassword.ErrTokenExpired {
		t.Errorf("Expected ErrTokenExpired, got %v", err)
	}
}

func TestSendVerificationEmailAndVerifyEmail(t *testing.T) {
	var callbackFired bool
	var callbackToken string

	_, p, _ := setupTestAuth(t,
		emailpassword.WithVerificationTokenExpiry(100*time.Millisecond),
		emailpassword.WithSendVerificationEmail(func(ctx context.Context, email, token string, expiresAt time.Time, extra map[string]any) error {
			callbackFired = true
			callbackToken = token
			return nil
		}),
	)
	ctx := context.Background()

	// 1. Invalid email format
	_, err := p.SendVerificationEmail(ctx, dto.SendVerificationEmailParams{Email: "bad-email"})
	if err != emailpassword.ErrInvalidEmail {
		t.Errorf("Expected ErrInvalidEmail, got %v", err)
	}

	// 2. Non-existent user
	_, err = p.SendVerificationEmail(ctx, dto.SendVerificationEmailParams{Email: "unknown@example.com"})
	if err != emailpassword.ErrUserNotFound {
		t.Errorf("Expected ErrUserNotFound, got %v", err)
	}

	// 3. Register user
	user, err := p.SignUp(ctx, dto.SignUpParams{
		Email:    "verifytest@example.com",
		Password: "password123",
		Name:     "Verify User",
	})
	if err != nil {
		t.Fatalf("SignUp failed: %v", err)
	}
	if user.EmailVerified {
		t.Error("Expected user.EmailVerified to be false initially")
	}

	// 4. Send verification email
	tokenRecord, err := p.SendVerificationEmail(ctx, dto.SendVerificationEmailParams{Email: "verifytest@example.com"})
	if err != nil {
		t.Fatalf("SendVerificationEmail failed: %v", err)
	}
	if !callbackFired || callbackToken != tokenRecord.Token {
		t.Error("Expected SendVerificationEmail callback to be executed")
	}

	// 5. Verify email with empty token
	_, err = p.VerifyEmail(ctx, dto.VerifyEmailParams{Token: ""})
	if err != emailpassword.ErrInvalidParameter {
		t.Errorf("Expected ErrInvalidParameter, got %v", err)
	}

	// 6. Verify email with invalid token
	_, err = p.VerifyEmail(ctx, dto.VerifyEmailParams{Token: "non_existent_token"})
	if err != emailpassword.ErrInvalidToken {
		t.Errorf("Expected ErrInvalidToken, got %v", err)
	}

	// 7. Successful verification
	verifiedUser, err := p.VerifyEmail(ctx, dto.VerifyEmailParams{Token: tokenRecord.Token})
	if err != nil {
		t.Fatalf("VerifyEmail failed: %v", err)
	}
	if !verifiedUser.EmailVerified {
		t.Error("Expected EmailVerified to be true")
	}

	// 8. Single-use token verification: second consumption must fail
	_, err = p.VerifyEmail(ctx, dto.VerifyEmailParams{Token: tokenRecord.Token})
	if err != emailpassword.ErrInvalidToken {
		t.Errorf("Expected ErrInvalidToken on reusing consumed token, got %v", err)
	}

	// 9. Token expiration test
	tokenRecordExpiry, err := p.SendVerificationEmail(ctx, dto.SendVerificationEmailParams{Email: "verifytest@example.com"})
	if err != nil {
		t.Fatalf("SendVerificationEmail failed: %v", err)
	}

	time.Sleep(150 * time.Millisecond)

	_, err = p.VerifyEmail(ctx, dto.VerifyEmailParams{Token: tokenRecordExpiry.Token})
	if err != emailpassword.ErrTokenExpired {
		t.Errorf("Expected ErrTokenExpired, got %v", err)
	}
}

func TestVerifyPassword(t *testing.T) {
	_, p, _ := setupTestAuth(t)
	ctx := context.Background()

	// 1. Missing parameter
	_, err := p.VerifyPassword(ctx, dto.VerifyPasswordParams{UserID: "", Password: "pwd"})
	if err != emailpassword.ErrInvalidParameter {
		t.Errorf("Expected ErrInvalidParameter, got %v", err)
	}

	// 2. Non-existent account
	_, err = p.VerifyPassword(ctx, dto.VerifyPasswordParams{UserID: "unknown_id", Password: "pwd"})
	if err != emailpassword.ErrAccountNotFound {
		t.Errorf("Expected ErrAccountNotFound, got %v", err)
	}

	// 3. Register user
	user, err := p.SignUp(ctx, dto.SignUpParams{
		Email:    "verifypass@example.com",
		Password: "SuperSecret123!",
		Name:     "VerifyPass User",
	})
	if err != nil {
		t.Fatalf("SignUp failed: %v", err)
	}

	// 4. Valid password check
	valid, err := p.VerifyPassword(ctx, dto.VerifyPasswordParams{
		UserID:   user.ID,
		Password: "SuperSecret123!",
	})
	if err != nil {
		t.Fatalf("VerifyPassword failed: %v", err)
	}
	if !valid {
		t.Error("Expected password to be valid")
	}

	// 5. Invalid password check
	valid, err = p.VerifyPassword(ctx, dto.VerifyPasswordParams{
		UserID:   user.ID,
		Password: "WrongPassword!",
	})
	if err != nil {
		t.Fatalf("VerifyPassword failed: %v", err)
	}
	if valid {
		t.Error("Expected password to be invalid")
	}
}

func TestEventEmissions(t *testing.T) {
	app, p, _ := setupTestAuth(t)
	ctx := context.Background()

	var (
		mu                           sync.Mutex
		signUpBeforeEmitted          bool
		signUpAfterEmitted           bool
		signInBeforeEmitted          bool
		signInAfterEmitted           bool
		passChangeBeforeEmitted      bool
		passChangeAfterEmitted       bool
		resetRequestedEmitted        bool
		resetCompletedEmitted        bool
		emailVerifRequestedEmitted   bool
		emailVerifiedEmitted         bool
	)

	app.Events().Subscribe(emailpassword.EventSignUpBefore, func(ctx context.Context, payload any) {
		mu.Lock()
		defer mu.Unlock()
		if req, ok := payload.(*emailpassword.SignUpEventPayload); ok && req.Params != nil {
			signUpBeforeEmitted = true
		}
	})

	app.Events().Subscribe(emailpassword.EventSignUpAfter, func(ctx context.Context, payload any) {
		mu.Lock()
		defer mu.Unlock()
		if req, ok := payload.(*emailpassword.SignUpEventPayload); ok && req.User != nil {
			signUpAfterEmitted = true
		}
	})

	app.Events().Subscribe(emailpassword.EventSignInBefore, func(ctx context.Context, payload any) {
		mu.Lock()
		defer mu.Unlock()
		if req, ok := payload.(*emailpassword.SignInEventPayload); ok && req.User != nil {
			signInBeforeEmitted = true
		}
	})

	app.Events().Subscribe(emailpassword.EventSignInAfter, func(ctx context.Context, payload any) {
		mu.Lock()
		defer mu.Unlock()
		if req, ok := payload.(*emailpassword.SignInEventPayload); ok && req.User != nil {
			signInAfterEmitted = true
		}
	})

	app.Events().Subscribe(emailpassword.EventPasswordChangeBefore, func(ctx context.Context, payload any) {
		mu.Lock()
		defer mu.Unlock()
		if req, ok := payload.(*emailpassword.PasswordChangeEventPayload); ok && req.UserID != "" {
			passChangeBeforeEmitted = true
		}
	})

	app.Events().Subscribe(emailpassword.EventPasswordChangeAfter, func(ctx context.Context, payload any) {
		mu.Lock()
		defer mu.Unlock()
		if req, ok := payload.(*emailpassword.PasswordChangeEventPayload); ok && req.UserID != "" {
			passChangeAfterEmitted = true
		}
	})

	app.Events().Subscribe(emailpassword.EventPasswordResetRequested, func(ctx context.Context, payload any) {
		mu.Lock()
		defer mu.Unlock()
		if req, ok := payload.(*emailpassword.PasswordResetRequestedEventPayload); ok && req.Token != "" {
			resetRequestedEmitted = true
		}
	})

	app.Events().Subscribe(emailpassword.EventPasswordResetCompleted, func(ctx context.Context, payload any) {
		mu.Lock()
		defer mu.Unlock()
		if req, ok := payload.(*emailpassword.PasswordResetCompletedEventPayload); ok && req.UserID != "" {
			resetCompletedEmitted = true
		}
	})

	app.Events().Subscribe(emailpassword.EventEmailVerificationRequested, func(ctx context.Context, payload any) {
		mu.Lock()
		defer mu.Unlock()
		if req, ok := payload.(*emailpassword.EmailVerificationRequestedEventPayload); ok && req.Token != "" {
			emailVerifRequestedEmitted = true
		}
	})

	app.Events().Subscribe(emailpassword.EventEmailVerified, func(ctx context.Context, payload any) {
		mu.Lock()
		defer mu.Unlock()
		if req, ok := payload.(*emailpassword.EmailVerifiedEventPayload); ok && req.User != nil {
			emailVerifiedEmitted = true
		}
	})

	// 1. SignUp
	user, err := p.SignUp(ctx, dto.SignUpParams{
		Email:    "events@example.com",
		Password: "password123",
		Name:     "Events User",
	})
	if err != nil {
		t.Fatalf("SignUp failed: %v", err)
	}

	// 2. SignIn
	_, err = p.SignIn(ctx, dto.SignInParams{
		Email:    "events@example.com",
		Password: "password123",
	})
	if err != nil {
		t.Fatalf("SignIn failed: %v", err)
	}

	// 3. ChangePassword
	err = p.ChangePassword(ctx, dto.ChangePasswordParams{
		UserID:          user.ID,
		CurrentPassword: "password123",
		NewPassword:     "newPassword456",
	})
	if err != nil {
		t.Fatalf("ChangePassword failed: %v", err)
	}

	// 4. ForgotPassword & ResetPassword
	resetToken, err := p.ForgotPassword(ctx, dto.ForgotPasswordParams{Email: "events@example.com"})
	if err != nil {
		t.Fatalf("ForgotPassword failed: %v", err)
	}
	err = p.ResetPassword(ctx, dto.ResetPasswordParams{
		Token:       resetToken.Token,
		NewPassword: "newerPassword789",
	})
	if err != nil {
		t.Fatalf("ResetPassword failed: %v", err)
	}

	// 5. SendVerificationEmail & VerifyEmail
	verifToken, err := p.SendVerificationEmail(ctx, dto.SendVerificationEmailParams{Email: "events@example.com"})
	if err != nil {
		t.Fatalf("SendVerificationEmail failed: %v", err)
	}
	_, err = p.VerifyEmail(ctx, dto.VerifyEmailParams{Token: verifToken.Token})
	if err != nil {
		t.Fatalf("VerifyEmail failed: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()

	if !signUpBeforeEmitted {
		t.Error("Expected EventSignUpBefore to be emitted")
	}
	if !signUpAfterEmitted {
		t.Error("Expected EventSignUpAfter to be emitted")
	}
	if !signInBeforeEmitted {
		t.Error("Expected EventSignInBefore to be emitted")
	}
	if !signInAfterEmitted {
		t.Error("Expected EventSignInAfter to be emitted")
	}
	if !passChangeBeforeEmitted {
		t.Error("Expected EventPasswordChangeBefore to be emitted")
	}
	if !passChangeAfterEmitted {
		t.Error("Expected EventPasswordChangeAfter to be emitted")
	}
	if !resetRequestedEmitted {
		t.Error("Expected EventPasswordResetRequested to be emitted")
	}
	if !resetCompletedEmitted {
		t.Error("Expected EventPasswordResetCompleted to be emitted")
	}
	if !emailVerifRequestedEmitted {
		t.Error("Expected EventEmailVerificationRequested to be emitted")
	}
	if !emailVerifiedEmitted {
		t.Error("Expected EventEmailVerified to be emitted")
	}
}

func TestSignUp_WithCreateUserParamsExtra(t *testing.T) {
	app, p, _ := setupTestAuth(t)
	ctx := context.Background()

	var interceptedRole string
	var extraFound bool

	app.Events().Subscribe(emailpassword.EventSignUpBefore, func(ctx context.Context, payload any) {
		if req, ok := payload.(*emailpassword.SignUpEventPayload); ok && req.Params != nil {
			req.Params.Set(emailpassword.ExtraKeyRole, "admin")
			req.Params.Set(emailpassword.ExtraKeyOrgID, "org_999")
		}
	})

	app.Events().Subscribe(emailpassword.EventSignUpAfter, func(ctx context.Context, payload any) {
		if req, ok := payload.(*emailpassword.SignUpEventPayload); ok && req.Params != nil {
			if val, ok := req.Params.Get(emailpassword.ExtraKeyRole); ok {
				interceptedRole, _ = val.(string)
				extraFound = true
			}
		}
	})

	_, err := p.SignUp(ctx, dto.SignUpParams{
		Email:    "extra@example.com",
		Password: "password123",
		Name:     "Extra User",
	})
	if err != nil {
		t.Fatalf("SignUp failed: %v", err)
	}

	if !extraFound || interceptedRole != "admin" {
		t.Errorf("Expected role 'admin' in CreateUserParams.Extra, got %v (found: %v)", interceptedRole, extraFound)
	}
}
