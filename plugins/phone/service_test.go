package phone_test

import (
	"context"
	"testing"
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	phone "github.com/BladiCreator/go-modular-auth-phone"
	"github.com/BladiCreator/go-modular-auth-phone/plugins"
	phonemem "github.com/BladiCreator/go-modular-auth-phone/store/memory"
	coremem "github.com/BladiCreator/go-modular-auth/store/memory"
)

func setupTestAuth(t *testing.T, opts ...phone.Option) (*auth.Auth, phone.Phone, *phone.MockProvider) {
	provider := phone.NewMockProvider()
	pStore := phonemem.New()

	defaultOpts := []phone.Option{
		phone.WithProvider(provider),
		phone.WithStore(pStore),
		phone.WithTTL(5 * time.Minute),
		phone.WithAllowSignUp(true),
	}
	allOpts := append(defaultOpts, opts...)

	a, err := auth.New(auth.Config{
		Store:   coremem.New(),
		Plugins: []auth.PluginModule{phone.New(allOpts...)},
	})
	if err != nil {
		t.Fatalf("failed to create core Auth: %v", err)
	}

	cap, err := auth.Get[phone.Phone](a)
	if err != nil {
		t.Fatalf("failed to retrieve phone capability: %v", err)
	}

	return a, cap, provider
}

func TestPhone_PluginRegistrationAndCapabilityLookup(t *testing.T) {
	a, p, _ := setupTestAuth(t)

	if p == nil {
		t.Fatal("phone capability should not be nil")
	}

	// Also verify retrieval through plugins.Phone alias
	aliasCap, err := auth.Get[plugins.Phone](a)
	if err != nil || aliasCap == nil {
		t.Fatalf("failed to retrieve via plugins.Phone: %v", err)
	}
}

func TestPhone_SignUpAndSignInFlow(t *testing.T) {
	ctx := context.Background()
	_, p, provider := setupTestAuth(t)

	phoneNumber := "+1 (202) 555-0123"

	// 1. Request OTP for unregistered phone (AllowSignUp = true)
	err := p.RequestOTP(ctx, phone.RequestOTPInput{
		PhoneNumber: phoneNumber,
	})
	if err != nil {
		t.Fatalf("RequestOTP failed: %v", err)
	}

	lastMsg := provider.LastMessage()
	if lastMsg == nil || lastMsg.Code == "" {
		t.Fatal("expected message to be dispatched with code")
	}
	code := lastMsg.Code

	// 2. Verify OTP -> Should auto sign-up and return authenticated session
	res, err := p.VerifyOTP(ctx, phone.VerifyOTPInput{
		PhoneNumber: phoneNumber,
		Code:        code,
	})
	if err != nil {
		t.Fatalf("VerifyOTP failed: %v", err)
	}

	if res.User == nil || res.Session == nil || res.Token == "" {
		t.Fatalf("incomplete AuthResult returned: %+v", res)
	}
	userID := res.User.ID

	// 3. Confirm phone record was persisted and marked verified
	rec, err := p.GetByUserID(ctx, userID)
	if err != nil || rec == nil {
		t.Fatalf("GetByUserID failed: %v", err)
	}
	if rec.PhoneNumber != "+12025550123" || !rec.Verified {
		t.Fatalf("unexpected phone record state: %+v", rec)
	}

	// 4. Existing user signs in again via OTP
	provider.Reset()
	err = p.RequestOTP(ctx, phone.RequestOTPInput{
		PhoneNumber: "+12025550123",
	})
	if err != nil {
		t.Fatalf("second RequestOTP failed: %v", err)
	}

	signInCode := provider.LastMessage().Code
	signInRes, err := p.VerifyOTP(ctx, phone.VerifyOTPInput{
		PhoneNumber: "+12025550123",
		Code:        signInCode,
	})
	if err != nil {
		t.Fatalf("second VerifyOTP failed: %v", err)
	}

	if signInRes.User.ID != userID {
		t.Fatalf("expected same user ID %s, got %s", userID, signInRes.User.ID)
	}
}

func TestPhone_VerificationFlowForExistingUser(t *testing.T) {
	ctx := context.Background()
	a, p, provider := setupTestAuth(t)

	// Register a core user via password signup
	signUpRes, err := a.SignUp(ctx, auth.SignUpInput{
		Email:    "existing@example.com",
		Password: "password123456",
	})
	if err != nil {
		t.Fatalf("SignUp failed: %v", err)
	}
	userID := signUpRes.User.ID

	// Initiate verification of a phone number
	newPhone := "+12025559999"
	err = p.RequestVerification(ctx, phone.RequestVerificationInput{
		UserID:      userID,
		PhoneNumber: newPhone,
	})
	if err != nil {
		t.Fatalf("RequestVerification failed: %v", err)
	}

	code := provider.LastMessage().Code
	confirmed, err := p.ConfirmVerification(ctx, phone.ConfirmVerificationInput{
		UserID:      userID,
		PhoneNumber: newPhone,
		Code:        code,
	})
	if err != nil {
		t.Fatalf("ConfirmVerification failed: %v", err)
	}

	if !confirmed.Verified || confirmed.PhoneNumber != newPhone {
		t.Fatalf("expected verified phone record, got: %+v", confirmed)
	}
}

func TestPhone_ChangeAndRemovalFlow(t *testing.T) {
	ctx := context.Background()
	_, p, provider := setupTestAuth(t)

	// Create user with phone
	_ = p.RequestOTP(ctx, phone.RequestOTPInput{PhoneNumber: "+12025551111"})
	res, _ := p.VerifyOTP(ctx, phone.VerifyOTPInput{
		PhoneNumber: "+12025551111",
		Code:        provider.LastMessage().Code,
	})
	userID := res.User.ID

	// Change phone number to +12025552222
	err := p.RequestChange(ctx, phone.RequestChangeInput{
		UserID:         userID,
		NewPhoneNumber: "+12025552222",
	})
	if err != nil {
		t.Fatalf("RequestChange failed: %v", err)
	}

	changeCode := provider.LastMessage().Code
	changed, err := p.ConfirmChange(ctx, phone.ConfirmChangeInput{
		UserID:         userID,
		NewPhoneNumber: "+12025552222",
		Code:           changeCode,
	})
	if err != nil {
		t.Fatalf("ConfirmChange failed: %v", err)
	}

	if changed.PhoneNumber != "+12025552222" {
		t.Fatalf("expected changed phone to be +12025552222, got %s", changed.PhoneNumber)
	}

	// Old phone should be free
	_, err = p.GetByPhone(ctx, "+12025551111")
	if err == nil {
		t.Fatal("expected old phone to not be found")
	}

	// Remove phone
	err = p.Remove(ctx, phone.RemoveInput{UserID: userID})
	if err != nil {
		t.Fatalf("Remove failed: %v", err)
	}

	_, err = p.GetByUserID(ctx, userID)
	if err == nil {
		t.Fatal("expected phone to be removed for user")
	}
}
