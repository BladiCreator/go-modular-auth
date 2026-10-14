package passwordpolicy_test

import (
	"context"
	"errors"
	"testing"
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	"github.com/BladiCreator/go-modular-auth/adapter"
	adaptermem "github.com/BladiCreator/go-modular-auth/adapter/memory"
	passwordpolicy "github.com/BladiCreator/go-modular-auth-password-policy"
	"github.com/BladiCreator/go-modular-auth-password-policy/plugins"
	corecache "github.com/BladiCreator/go-modular-auth/cache/memory"
	"github.com/BladiCreator/go-modular-auth/verification"
)

func setupTestAuth(t *testing.T, opts ...passwordpolicy.Option) (*auth.Auth, plugins.PasswordPolicy, adapter.Adapter) {
	t.Helper()
	ad := adaptermem.New()
	cCache := corecache.New()

	policyModule := passwordpolicy.New(opts...)

	a, err := auth.New(auth.Config{
		Adapter: ad,
		Cache:   cCache,
		Plugins: []auth.PluginModule{policyModule},
	})
	if err != nil {
		t.Fatalf("auth.New failed: %v", err)
	}

	policyPlugin, err := auth.Get[plugins.PasswordPolicy](a)
	if err != nil {
		t.Fatalf("auth.Get[plugins.PasswordPolicy] failed: %v", err)
	}

	return a, policyPlugin, ad
}

func TestPasswordPolicy_Hook_BeforeSignUp(t *testing.T) {
	ctx := context.Background()
	policy := passwordpolicy.Policy{
		MinLength:         10,
		MaxLength:         64,
		RequireUppercase:  true,
		RequireLowercase:  true,
		RequireDigit:      true,
		RequireSymbol:     true,
		HistoryCount:      3,
		RejectCompromised: true,
	}

	a, _, _ := setupTestAuth(t, passwordpolicy.WithPolicy(policy))

	// 1. Password too short
	_, err := a.SignUp(ctx, auth.SignUpInput{
		Email:    "test1@example.com",
		Password: "Short1!",
	})
	if !errors.Is(err, passwordpolicy.ErrPasswordTooShort) {
		t.Errorf("expected ErrPasswordTooShort, got: %v", err)
	}

	// 2. Missing uppercase
	_, err = a.SignUp(ctx, auth.SignUpInput{
		Email:    "test2@example.com",
		Password: "lowercase123!",
	})
	if !errors.Is(err, passwordpolicy.ErrPasswordRequiresUppercase) {
		t.Errorf("expected ErrPasswordRequiresUppercase, got: %v", err)
	}

	// 3. Missing digit
	_, err = a.SignUp(ctx, auth.SignUpInput{
		Email:    "test3@example.com",
		Password: "NoDigitsHere!!",
	})
	if !errors.Is(err, passwordpolicy.ErrPasswordRequiresDigit) {
		t.Errorf("expected ErrPasswordRequiresDigit, got: %v", err)
	}

	// 4. Missing symbol
	_, err = a.SignUp(ctx, auth.SignUpInput{
		Email:    "test4@example.com",
		Password: "NoSymbolsHere123",
	})
	if !errors.Is(err, passwordpolicy.ErrPasswordRequiresSymbol) {
		t.Errorf("expected ErrPasswordRequiresSymbol, got: %v", err)
	}

	// 5. Compromised password
	_, err = a.SignUp(ctx, auth.SignUpInput{
		Email:    "test5@example.com",
		Password: "password123",
	})
	if !errors.Is(err, passwordpolicy.ErrPasswordCompromised) && !errors.Is(err, passwordpolicy.ErrPasswordRequiresUppercase) {
		t.Errorf("expected compromise or complexity failure, got: %v", err)
	}

	// 6. Valid password meeting all criteria
	res, err := a.SignUp(ctx, auth.SignUpInput{
		Email:    "test_valid@example.com",
		Password: "ValidPassword123!",
	})
	if err != nil {
		t.Fatalf("expected SignUp to succeed with valid password, got: %v", err)
	}
	if res.User == nil {
		t.Fatalf("expected user created")
	}
}

func TestPasswordPolicy_PasswordHistory_ChangePasswordReuse(t *testing.T) {
	ctx := context.Background()
	policy := passwordpolicy.Policy{
		MinLength:         8,
		MaxLength:         64,
		RequireUppercase:  true,
		RequireLowercase:  true,
		RequireDigit:      true,
		HistoryCount:      2,
		RejectCompromised: false,
	}

	a, policyPlugin, _ := setupTestAuth(t, passwordpolicy.WithPolicy(policy))

	// 1. Initial SignUp with PasswordOne1
	signUpRes, err := a.SignUp(ctx, auth.SignUpInput{
		Email:    "alice_hist@example.com",
		Password: "PasswordOne1",
	})
	if err != nil {
		t.Fatalf("SignUp failed: %v", err)
	}
	userID := signUpRes.User.ID

	// Verify history was automatically populated by AfterSignUp hook
	hist, err := policyPlugin.GetHistory(ctx, userID, 10)
	if err != nil || len(hist) != 1 {
		t.Fatalf("expected 1 history record after SignUp, got %d (err: %v)", len(hist), err)
	}

	// 2. Change password to PasswordTwo2
	err = policyPlugin.ChangePassword(ctx, passwordpolicy.ChangePasswordInput{
		UserID:          userID,
		CurrentPassword: "PasswordOne1",
		NewPassword:     "PasswordTwo2",
	})
	if err != nil {
		t.Fatalf("ChangePassword failed: %v", err)
	}

	// 3. Attempt to reuse PasswordOne1 -> must fail with ErrPasswordInHistory
	err = policyPlugin.ChangePassword(ctx, passwordpolicy.ChangePasswordInput{
		UserID:          userID,
		CurrentPassword: "PasswordTwo2",
		NewPassword:     "PasswordOne1",
	})
	if !errors.Is(err, passwordpolicy.ErrPasswordInHistory) {
		t.Errorf("expected ErrPasswordInHistory for PasswordOne1, got: %v", err)
	}

	// 4. Attempt to reuse current PasswordTwo2 -> must fail with ErrPasswordInHistory
	err = policyPlugin.ChangePassword(ctx, passwordpolicy.ChangePasswordInput{
		UserID:          userID,
		CurrentPassword: "PasswordTwo2",
		NewPassword:     "PasswordTwo2",
	})
	if !errors.Is(err, passwordpolicy.ErrPasswordInHistory) {
		t.Errorf("expected ErrPasswordInHistory for current password, got: %v", err)
	}

	// 5. Change to PasswordThree3
	err = policyPlugin.ChangePassword(ctx, passwordpolicy.ChangePasswordInput{
		UserID:          userID,
		CurrentPassword: "PasswordTwo2",
		NewPassword:     "PasswordThree3",
	})
	if err != nil {
		t.Fatalf("ChangePassword to PasswordThree3 failed: %v", err)
	}

	// 6. Change to PasswordFour4 (now history retains only last 2: Three and Four)
	err = policyPlugin.ChangePassword(ctx, passwordpolicy.ChangePasswordInput{
		UserID:          userID,
		CurrentPassword: "PasswordThree3",
		NewPassword:     "PasswordFour4",
	})
	if err != nil {
		t.Fatalf("ChangePassword to PasswordFour4 failed: %v", err)
	}

	// 7. PasswordOne1 is now pushed out of the 2-item history window -> reuse now allowed!
	err = policyPlugin.ChangePassword(ctx, passwordpolicy.ChangePasswordInput{
		UserID:          userID,
		CurrentPassword: "PasswordFour4",
		NewPassword:     "PasswordOne1",
	})
	if err != nil {
		t.Fatalf("expected reuse of PasswordOne1 to succeed after history window eviction, got: %v", err)
	}
}

func TestPasswordPolicy_ResetPassword_Enforcement(t *testing.T) {
	ctx := context.Background()
	policy := passwordpolicy.Policy{
		MinLength:         10,
		RequireUppercase:  true,
		RequireDigit:      true,
		HistoryCount:      2,
		RejectCompromised: true,
	}

	a, policyPlugin, _ := setupTestAuth(t, passwordpolicy.WithPolicy(policy))

	signUpRes, err := a.SignUp(ctx, auth.SignUpInput{
		Email:    "reset_user@example.com",
		Password: "InitialPassword123!",
	})
	if err != nil {
		t.Fatalf("SignUp failed: %v", err)
	}
	userID := signUpRes.User.ID

	// Issue a reset token directly via Core
	token, err := a.IssueToken(ctx, verification.PurposePasswordReset, userID, 15*time.Minute)
	if err != nil {
		t.Fatalf("IssueToken failed: %v", err)
	}

	// Attempt reset with weak password -> must fail
	err = policyPlugin.ResetPassword(ctx, passwordpolicy.ResetPasswordInput{
		Token:       token,
		NewPassword: "short",
	})
	if !errors.Is(err, passwordpolicy.ErrPasswordTooShort) {
		t.Errorf("expected ErrPasswordTooShort, got: %v", err)
	}

	// Attempt reset with compliant password -> must succeed
	err = policyPlugin.ResetPassword(ctx, passwordpolicy.ResetPasswordInput{
		Token:       token,
		NewPassword: "BrandNewPassword999!",
	})
	if err != nil {
		t.Fatalf("ResetPassword failed: %v", err)
	}

	// Verify SignIn with the new reset password works
	signInRes, err := a.SignIn(ctx, auth.SignInInput{
		Email:    "reset_user@example.com",
		Password: "BrandNewPassword999!",
	})
	if err != nil || signInRes.User == nil {
		t.Fatalf("SignIn with reset password failed: %v", err)
	}
}
