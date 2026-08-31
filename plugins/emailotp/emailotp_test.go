package emailotp_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/BladiCreator/go-modular-auth/domain/dto"
	"github.com/BladiCreator/go-modular-auth/domain/entity"
	"github.com/BladiCreator/go-modular-auth/domain/repository"
	"github.com/BladiCreator/go-modular-auth/plugin"
	"github.com/BladiCreator/go-modular-auth/plugins/emailotp"
	"github.com/asaskevich/EventBus"
	"github.com/google/uuid"
)

// In-Memory Test Repository implementing emailotp.Repository
type testRepo struct {
	*repository.MemorySessionRepository
	mu            sync.Mutex
	users         map[string]*entity.User
	accounts      map[string]*entity.Account
	userAccounts  map[string]map[string]*entity.Account // userID -> providerID -> Account
	verifications map[string]*emailotp.VerificationRecord
}

func newTestRepo() *testRepo {
	return &testRepo{
		MemorySessionRepository: repository.NewMemorySessionRepository(),
		users:                   make(map[string]*entity.User),
		accounts:                make(map[string]*entity.Account),
		userAccounts:            make(map[string]map[string]*entity.Account),
		verifications:           make(map[string]*emailotp.VerificationRecord),
	}
}

func (r *testRepo) FindVerificationValue(ctx context.Context, identifier string) (*emailotp.VerificationRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	rec, ok := r.verifications[identifier]
	if !ok {
		return nil, nil
	}
	cloned := *rec
	return &cloned, nil
}

func (r *testRepo) CreateVerificationValue(ctx context.Context, record *emailotp.VerificationRecord) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	cloned := *record
	r.verifications[record.Identifier] = &cloned
	return nil
}

func (r *testRepo) UpdateVerificationValue(ctx context.Context, identifier, value string, expiresAt time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	rec, ok := r.verifications[identifier]
	if !ok {
		return nil
	}
	rec.Value = value
	rec.ExpiresAt = expiresAt
	rec.UpdatedAt = time.Now()
	return nil
}

func (r *testRepo) DeleteVerificationValue(ctx context.Context, identifier string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	delete(r.verifications, identifier)
	return nil
}

func (r *testRepo) ConsumeVerificationValue(ctx context.Context, identifier string) (*emailotp.VerificationRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	rec, ok := r.verifications[identifier]
	if !ok {
		return nil, nil
	}
	delete(r.verifications, identifier)
	cloned := *rec
	return &cloned, nil
}

func (r *testRepo) GetUserByEmail(ctx context.Context, email string) (*entity.User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, u := range r.users {
		if strings.EqualFold(u.Email, email) {
			cloned := *u
			return &cloned, nil
		}
	}
	return nil, emailotp.ErrUserNotFound
}

func (r *testRepo) GetUserByID(ctx context.Context, id string) (*entity.User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	u, ok := r.users[id]
	if !ok {
		return nil, emailotp.ErrUserNotFound
	}
	cloned := *u
	return &cloned, nil
}

func (r *testRepo) CreateUser(ctx context.Context, params *dto.CreateUserParams) (*entity.User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	u := &entity.User{
		ID:            "usr_" + uuid.NewString(),
		Email:         params.Email,
		Name:          params.Name,
		Role:          params.Role,
		EmailVerified: false,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}
	r.users[u.ID] = u
	cloned := *u
	return &cloned, nil
}

func (r *testRepo) UpdateUser(ctx context.Context, user *entity.User) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, ok := r.users[user.ID]; !ok {
		return emailotp.ErrUserNotFound
	}
	cloned := *user
	r.users[user.ID] = &cloned
	return nil
}

func (r *testRepo) GetAccountByUserIDAndProvider(ctx context.Context, userID, providerID string) (*entity.Account, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if userAccs, ok := r.userAccounts[userID]; ok {
		if acc, ok := userAccs[providerID]; ok {
			cloned := *acc
			return &cloned, nil
		}
	}
	return nil, emailotp.ErrAccountNotFound
}

func (r *testRepo) CreateAccount(ctx context.Context, account *entity.Account) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	cloned := *account
	r.accounts[account.ID] = &cloned
	if _, ok := r.userAccounts[account.UserID]; !ok {
		r.userAccounts[account.UserID] = make(map[string]*entity.Account)
	}
	r.userAccounts[account.UserID][account.Provider] = &cloned
	return nil
}

func (r *testRepo) UpdateAccountPassword(ctx context.Context, userID, passwordHash string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if userAccs, ok := r.userAccounts[userID]; ok {
		if acc, ok := userAccs["credential"]; ok {
			acc.Password = passwordHash
			acc.UpdatedAt = time.Now()
			return nil
		}
	}
	return emailotp.ErrAccountNotFound
}

func (r *testRepo) DeleteCredentialAccount(ctx context.Context, userID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if userAccs, ok := r.userAccounts[userID]; ok {
		if acc, ok := userAccs["credential"]; ok {
			delete(r.accounts, acc.ID)
			delete(userAccs, "credential")
		}
	}
	return nil
}

func setupTestPlugin(t *testing.T, opts ...emailotp.Option) (*emailotp.Plugin, *testRepo, *[]emailotp.SendEmailData, EventBus.Bus) {
	repo := newTestRepo()
	var sentEmails []emailotp.SendEmailData
	var mu sync.Mutex

	bus := EventBus.New()
	pCtx := plugin.NewContext(nil, bus)

	defaultOpts := []emailotp.Option{
		emailotp.WithSendVerificationOTP(func(ctx context.Context, data emailotp.SendEmailData) error {
			mu.Lock()
			defer mu.Unlock()
			sentEmails = append(sentEmails, data)
			return nil
		}),
	}
	defaultOpts = append(defaultOpts, opts...)

	p := emailotp.New(repo, defaultOpts...)
	if err := p.Init(pCtx); err != nil {
		t.Fatalf("failed to init plugin: %v", err)
	}

	return p, repo, &sentEmails, bus
}

func TestSendVerificationOTP(t *testing.T) {
	ctx := context.Background()
	p, _, sent, _ := setupTestPlugin(t)

	// Valid send
	res, err := p.SendVerificationOTP(ctx, &emailotp.SendVerificationOTPParams{
		Email: "user@example.com",
		Type:  emailotp.OTPTypeEmailVerification,
	})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if !res.Success || len(*sent) != 1 {
		t.Fatalf("expected success and 1 sent email, got success=%v, count=%d", res.Success, len(*sent))
	}
	if (*sent)[0].Email != "user@example.com" || len((*sent)[0].OTP) != 6 {
		t.Fatalf("unexpected sent email data: %+v", (*sent)[0])
	}

	// Invalid email
	_, err = p.SendVerificationOTP(ctx, &emailotp.SendVerificationOTPParams{
		Email: "invalid-email",
		Type:  emailotp.OTPTypeEmailVerification,
	})
	if !errors.Is(err, emailotp.ErrInvalidEmail) {
		t.Fatalf("expected ErrInvalidEmail, got %v", err)
	}

	// Invalid OTP type
	_, err = p.SendVerificationOTP(ctx, &emailotp.SendVerificationOTPParams{
		Email: "user@example.com",
		Type:  "invalid-type",
	})
	if !errors.Is(err, emailotp.ErrInvalidOTPType) {
		t.Fatalf("expected ErrInvalidOTPType, got %v", err)
	}
}

func TestVerifyEmailOTP(t *testing.T) {
	ctx := context.Background()
	p, repo, sent, _ := setupTestPlugin(t, emailotp.WithAutoSignInAfterVerification(true))

	// Provision user
	user, err := repo.CreateUser(ctx, &dto.CreateUserParams{
		Email: "verify@example.com",
		Name:  "Verify User",
	})
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	// Send OTP
	_, err = p.SendVerificationOTP(ctx, &emailotp.SendVerificationOTPParams{
		Email: user.Email,
		Type:  emailotp.OTPTypeEmailVerification,
	})
	if err != nil {
		t.Fatalf("failed to send OTP: %v", err)
	}

	otpCode := (*sent)[0].OTP

	// Verify with correct OTP
	vRes, err := p.VerifyEmailOTP(ctx, &emailotp.VerifyEmailOTPParams{
		Email: user.Email,
		OTP:   otpCode,
	})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if !vRes.Success || !vRes.User.EmailVerified {
		t.Fatalf("expected emailVerified=true, got %+v", vRes.User)
	}
	if vRes.SessionToken == "" || vRes.Session == nil {
		t.Fatalf("expected auto-created session, got nil")
	}

	// Replay attack: verifying again should fail
	_, err = p.VerifyEmailOTP(ctx, &emailotp.VerifyEmailOTPParams{
		Email: user.Email,
		OTP:   otpCode,
	})
	if !errors.Is(err, emailotp.ErrInvalidOTP) {
		t.Fatalf("expected ErrInvalidOTP on replay, got %v", err)
	}
}

func TestAttemptBudgetAndLockout(t *testing.T) {
	ctx := context.Background()
	p, repo, sent, _ := setupTestPlugin(t, emailotp.WithAllowedAttempts(3))

	user, _ := repo.CreateUser(ctx, &dto.CreateUserParams{
		Email: "attempts@example.com",
		Name:  "Attempts User",
	})

	_, _ = p.SendVerificationOTP(ctx, &emailotp.SendVerificationOTPParams{
		Email: user.Email,
		Type:  emailotp.OTPTypeEmailVerification,
	})
	correctOTP := (*sent)[0].OTP

	// Attempt 1: wrong code -> ErrInvalidOTP
	_, err := p.VerifyEmailOTP(ctx, &emailotp.VerifyEmailOTPParams{
		Email: user.Email,
		OTP:   "000000",
	})
	if !errors.Is(err, emailotp.ErrInvalidOTP) {
		t.Fatalf("attempt 1: expected ErrInvalidOTP, got %v", err)
	}

	// Attempt 2: wrong code -> ErrInvalidOTP
	_, err = p.VerifyEmailOTP(ctx, &emailotp.VerifyEmailOTPParams{
		Email: user.Email,
		OTP:   "111111",
	})
	if !errors.Is(err, emailotp.ErrInvalidOTP) {
		t.Fatalf("attempt 2: expected ErrInvalidOTP, got %v", err)
	}

	// Attempt 3: wrong code -> ErrTooManyAttempts
	_, err = p.VerifyEmailOTP(ctx, &emailotp.VerifyEmailOTPParams{
		Email: user.Email,
		OTP:   "222222",
	})
	if !errors.Is(err, emailotp.ErrTooManyAttempts) {
		t.Fatalf("attempt 3: expected ErrTooManyAttempts, got %v", err)
	}

	// Attempt 4: entering correct code now should fail because record was consumed/locked out
	_, err = p.VerifyEmailOTP(ctx, &emailotp.VerifyEmailOTPParams{
		Email: user.Email,
		OTP:   correctOTP,
	})
	if !errors.Is(err, emailotp.ErrInvalidOTP) && !errors.Is(err, emailotp.ErrTooManyAttempts) {
		t.Fatalf("attempt 4: expected rejection after lockout, got %v", err)
	}
}

func TestSignInEmailOTP(t *testing.T) {
	ctx := context.Background()
	p, repo, sent, _ := setupTestPlugin(t, emailotp.WithDisableSignUp(false))

	// 1. Passwordless sign up for new user
	_, err := p.SendVerificationOTP(ctx, &emailotp.SendVerificationOTPParams{
		Email: "NEWUSER@Example.COM ",
		Type:  emailotp.OTPTypeSignIn,
	})
	if err != nil {
		t.Fatalf("failed to send OTP: %v", err)
	}
	otp1 := (*sent)[0].OTP

	res, err := p.SignInEmailOTP(ctx, &emailotp.SignInEmailOTPParams{
		Email: "newuser@example.com",
		OTP:   otp1,
		Name:  "New Sign In User",
	})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if !res.IsNewUser || !res.User.EmailVerified || res.SessionToken == "" {
		t.Fatalf("expected new user created with verified email, got %+v", res)
	}

	// 2. Sign in existing user
	_, _ = p.SendVerificationOTP(ctx, &emailotp.SendVerificationOTPParams{
		Email: "newuser@example.com",
		Type:  emailotp.OTPTypeSignIn,
	})
	otp2 := (*sent)[1].OTP

	res2, err := p.SignInEmailOTP(ctx, &emailotp.SignInEmailOTPParams{
		Email: "newuser@example.com",
		OTP:   otp2,
	})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if res2.IsNewUser || res2.User.ID != res.User.ID {
		t.Fatalf("expected existing user login, got %+v", res2)
	}

	// 3. Test with DisableSignUp = true
	pNoSignUp, _, sentNoSignUp, _ := setupTestPlugin(t, emailotp.WithDisableSignUp(true))
	_, _ = pNoSignUp.SendVerificationOTP(ctx, &emailotp.SendVerificationOTPParams{
		Email: "unregistered@example.com",
		Type:  emailotp.OTPTypeSignIn,
	})
	otp3 := (*sentNoSignUp)[0].OTP

	_, err = pNoSignUp.SignInEmailOTP(ctx, &emailotp.SignInEmailOTPParams{
		Email: "unregistered@example.com",
		OTP:   otp3,
	})
	if !errors.Is(err, emailotp.ErrUserNotFound) {
		t.Fatalf("expected ErrUserNotFound when signup disabled, got %v", err)
	}
	_ = repo
}

func TestPasswordReset(t *testing.T) {
	ctx := context.Background()
	p, repo, sent, _ := setupTestPlugin(t, emailotp.WithRevokeSessionsOnPasswordReset(true))

	user, _ := repo.CreateUser(ctx, &dto.CreateUserParams{
		Email: "reset@example.com",
		Name:  "Reset User",
	})
	sess, _ := repo.CreateSession(ctx, &dto.CreateSessionParams{
		UserID:    user.ID,
		Token:     "active-session-token",
		ExpiresAt: time.Now().Add(24 * time.Hour),
		CreatedAt: time.Now(),
	})

	// Request reset
	rRes, err := p.RequestPasswordResetEmailOTP(ctx, &emailotp.RequestPasswordResetParams{
		Email: user.Email,
	})
	if err != nil || !rRes.Success {
		t.Fatalf("expected success, got %v", err)
	}

	resetOTP := (*sent)[0].OTP

	// Password too short
	_, err = p.ResetPasswordEmailOTP(ctx, &emailotp.ResetPasswordParams{
		Email:       user.Email,
		OTP:         resetOTP,
		NewPassword: "short",
	})
	if !errors.Is(err, emailotp.ErrPasswordTooShort) {
		t.Fatalf("expected ErrPasswordTooShort, got %v", err)
	}

	// Valid password reset
	_, err = p.ResetPasswordEmailOTP(ctx, &emailotp.ResetPasswordParams{
		Email:       user.Email,
		OTP:         resetOTP,
		NewPassword: "new-strong-password-123",
	})
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}

	// Verify active session was revoked
	if _, err := repo.GetSessionByToken(ctx, sess.Token); err == nil {
		t.Fatalf("expected active session to be revoked on password reset")
	}

	// Verify account has updated password
	acc, err := repo.GetAccountByUserIDAndProvider(ctx, user.ID, "credential")
	if err != nil || acc.Password == "" {
		t.Fatalf("expected updated credential account password, got %v", err)
	}
}

func TestEmailChangeFlow(t *testing.T) {
	ctx := context.Background()

	// 1. Feature disabled
	pDisabled, repo, _, _ := setupTestPlugin(t, emailotp.WithChangeEmail(false, false))
	u, _ := repo.CreateUser(ctx, &dto.CreateUserParams{Email: "old@example.com", Name: "User"})
	_, err := pDisabled.RequestEmailChangeEmailOTP(ctx, &emailotp.RequestEmailChangeParams{
		UserID:   u.ID,
		NewEmail: "new@example.com",
	})
	if !errors.Is(err, emailotp.ErrChangeEmailDisabled) {
		t.Fatalf("expected ErrChangeEmailDisabled, got %v", err)
	}

	// 2. Simple email change (VerifyCurrentEmail = false)
	pEnabled, repoEnabled, sentEnabled, _ := setupTestPlugin(t, emailotp.WithChangeEmail(true, false))
	u2, _ := repoEnabled.CreateUser(ctx, &dto.CreateUserParams{Email: "current@example.com", Name: "User 2"})

	reqRes, err := pEnabled.RequestEmailChangeEmailOTP(ctx, &emailotp.RequestEmailChangeParams{
		UserID:   u2.ID,
		NewEmail: "brandnew@example.com",
	})
	if err != nil || !reqRes.Success {
		t.Fatalf("failed request change email: %v", err)
	}
	changeOTP := (*sentEnabled)[0].OTP

	changeRes, err := pEnabled.ChangeEmailEmailOTP(ctx, &emailotp.ChangeEmailParams{
		UserID:   u2.ID,
		NewEmail: "brandnew@example.com",
		OTP:      changeOTP,
	})
	if err != nil || !changeRes.Success {
		t.Fatalf("failed to confirm change email: %v", err)
	}
	if changeRes.User.Email != "brandnew@example.com" {
		t.Fatalf("expected user email to be updated to brandnew@example.com, got %s", changeRes.User.Email)
	}

	// 3. Double-step verification (VerifyCurrentEmail = true)
	pDouble, repoDouble, sentDouble, _ := setupTestPlugin(t, emailotp.WithChangeEmail(true, true))
	u3, _ := repoDouble.CreateUser(ctx, &dto.CreateUserParams{Email: "secure@example.com", Name: "Secure User"})

	// Step A: Send OTP to current email
	_, _ = pDouble.SendVerificationOTP(ctx, &emailotp.SendVerificationOTPParams{
		Email: u3.Email,
		Type:  emailotp.OTPTypeChangeEmail,
	})
	currentEmailOTP := (*sentDouble)[0].OTP

	// Step B: Request change providing current email OTP
	_, err = pDouble.RequestEmailChangeEmailOTP(ctx, &emailotp.RequestEmailChangeParams{
		UserID:   u3.ID,
		NewEmail: "secure-new@example.com",
		OTP:      currentEmailOTP,
	})
	if err != nil {
		t.Fatalf("failed to request change email with current OTP: %v", err)
	}
	newEmailOTP := (*sentDouble)[1].OTP

	// Step C: Confirm with new email OTP
	confRes, err := pDouble.ChangeEmailEmailOTP(ctx, &emailotp.ChangeEmailParams{
		UserID:   u3.ID,
		NewEmail: "secure-new@example.com",
		OTP:      newEmailOTP,
	})
	if err != nil || !confRes.Success {
		t.Fatalf("failed to complete double email change: %v", err)
	}
	if confRes.User.Email != "secure-new@example.com" {
		t.Fatalf("expected email updated, got %s", confRes.User.Email)
	}
}

func TestStoreOTPModes(t *testing.T) {
	ctx := context.Background()

	// Mode 1: Plain
	pPlain, _, sentPlain, _ := setupTestPlugin(t, emailotp.WithStoreOTP(emailotp.StoreOTPPlain))
	_, _ = pPlain.SendVerificationOTP(ctx, &emailotp.SendVerificationOTPParams{
		Email: "plain@example.com",
		Type:  emailotp.OTPTypeSignIn,
	})
	plainOTP := (*sentPlain)[0].OTP
	getPlain, err := pPlain.GetVerificationOTP(ctx, &emailotp.GetVerificationOTPParams{
		Email: "plain@example.com",
		Type:  emailotp.OTPTypeSignIn,
	})
	if err != nil || getPlain.OTP != plainOTP {
		t.Fatalf("plain mode: expected plain OTP %s, got %v", plainOTP, getPlain)
	}

	// Mode 2: Hashed
	pHashed, _, sentHashed, _ := setupTestPlugin(t, emailotp.WithStoreOTP(emailotp.StoreOTPHashed))
	_, _ = pHashed.SendVerificationOTP(ctx, &emailotp.SendVerificationOTPParams{
		Email: "hashed@example.com",
		Type:  emailotp.OTPTypeSignIn,
	})
	hashedOTP := (*sentHashed)[0].OTP
	// GetVerificationOTP should fail
	_, err = pHashed.GetVerificationOTP(ctx, &emailotp.GetVerificationOTPParams{
		Email: "hashed@example.com",
		Type:  emailotp.OTPTypeSignIn,
	})
	if !errors.Is(err, emailotp.ErrCannotRetrieveHashed) {
		t.Fatalf("hashed mode: expected ErrCannotRetrieveHashed, got %v", err)
	}
	// Check verification should succeed
	chkRes, err := pHashed.CheckVerificationOTP(ctx, &emailotp.CheckVerificationOTPParams{
		Email: "hashed@example.com",
		Type:  emailotp.OTPTypeSignIn,
		OTP:   hashedOTP,
	})
	if err != nil || !chkRes.Success {
		t.Fatalf("hashed mode: expected check success, got %v", err)
	}

	// Mode 3: Encrypted
	secretKey := "super-secret-cryptographic-key-12345"
	pEnc, _, sentEnc, _ := setupTestPlugin(t, emailotp.WithStoreOTP(emailotp.StoreOTPEncrypted, secretKey))
	_, _ = pEnc.SendVerificationOTP(ctx, &emailotp.SendVerificationOTPParams{
		Email: "enc@example.com",
		Type:  emailotp.OTPTypeSignIn,
	})
	encOTP := (*sentEnc)[0].OTP
	getEnc, err := pEnc.GetVerificationOTP(ctx, &emailotp.GetVerificationOTPParams{
		Email: "enc@example.com",
		Type:  emailotp.OTPTypeSignIn,
	})
	if err != nil || getEnc.OTP != encOTP {
		t.Fatalf("encrypted mode: expected decrypted OTP %s, got %v", encOTP, getEnc)
	}
}

func TestResendStrategy(t *testing.T) {
	ctx := context.Background()

	// Rotate strategy: always creates new OTP
	pRotate, _, sentRotate, _ := setupTestPlugin(t, emailotp.WithResendStrategy(emailotp.ResendStrategyRotate))
	_, _ = pRotate.SendVerificationOTP(ctx, &emailotp.SendVerificationOTPParams{Email: "rot@example.com", Type: emailotp.OTPTypeSignIn})
	_, _ = pRotate.SendVerificationOTP(ctx, &emailotp.SendVerificationOTPParams{Email: "rot@example.com", Type: emailotp.OTPTypeSignIn})
	if len(*sentRotate) != 2 {
		t.Fatalf("expected 2 sent emails")
	}

	// Reuse strategy: reuses existing active OTP
	pReuse, _, sentReuse, _ := setupTestPlugin(t,
		emailotp.WithStoreOTP(emailotp.StoreOTPPlain),
		emailotp.WithResendStrategy(emailotp.ResendStrategyReuse),
	)
	_, _ = pReuse.SendVerificationOTP(ctx, &emailotp.SendVerificationOTPParams{Email: "reuse@example.com", Type: emailotp.OTPTypeSignIn})
	_, _ = pReuse.SendVerificationOTP(ctx, &emailotp.SendVerificationOTPParams{Email: "reuse@example.com", Type: emailotp.OTPTypeSignIn})
	if len(*sentReuse) != 2 {
		t.Fatalf("expected 2 sent emails")
	}
	if (*sentReuse)[0].OTP != (*sentReuse)[1].OTP {
		t.Fatalf("expected reused OTP code, got %s vs %s", (*sentReuse)[0].OTP, (*sentReuse)[1].OTP)
	}
}

func TestConcurrentAtomicVerification(t *testing.T) {
	ctx := context.Background()
	p, repo, sent, _ := setupTestPlugin(t)

	user, _ := repo.CreateUser(ctx, &dto.CreateUserParams{
		Email: "concurrency@example.com",
		Name:  "Concurrent User",
	})

	_, _ = p.SendVerificationOTP(ctx, &emailotp.SendVerificationOTPParams{
		Email: user.Email,
		Type:  emailotp.OTPTypeEmailVerification,
	})
	otp := (*sent)[0].OTP

	concurrency := 50
	var wg sync.WaitGroup
	wg.Add(concurrency)

	var successCount int64
	var failureCount int64
	var mu sync.Mutex

	for i := 0; i < concurrency; i++ {
		go func() {
			defer wg.Done()
			res, err := p.VerifyEmailOTP(ctx, &emailotp.VerifyEmailOTPParams{
				Email: user.Email,
				OTP:   otp,
			})
			mu.Lock()
			defer mu.Unlock()
			if err == nil && res.Success {
				successCount++
			} else {
				failureCount++
			}
		}()
	}

	wg.Wait()

	if successCount != 1 {
		t.Fatalf("expected EXACTLY 1 successful atomic verification, got %d (failures: %d)", successCount, failureCount)
	}
	if failureCount != int64(concurrency-1) {
		t.Fatalf("expected %d failures, got %d", concurrency-1, failureCount)
	}
}

func TestEventBusPublishing(t *testing.T) {
	ctx := context.Background()
	p, repo, sent, bus := setupTestPlugin(t)

	var receivedSentEvent bool
	var receivedVerifiedEvent bool
	var mu sync.Mutex

	_ = bus.Subscribe(emailotp.EventEmailOTPSent, func(payload *emailotp.OTPSentPayload) {
		mu.Lock()
		defer mu.Unlock()
		if payload.Email == "events@example.com" {
			receivedSentEvent = true
		}
	})

	_ = bus.Subscribe(emailotp.EventEmailOTPVerified, func(payload *emailotp.OTPVerifiedPayload) {
		mu.Lock()
		defer mu.Unlock()
		if payload.Email == "events@example.com" {
			receivedVerifiedEvent = true
		}
	})

	user, _ := repo.CreateUser(ctx, &dto.CreateUserParams{
		Email: "events@example.com",
		Name:  "Events User",
	})

	_, _ = p.SendVerificationOTP(ctx, &emailotp.SendVerificationOTPParams{
		Email: user.Email,
		Type:  emailotp.OTPTypeEmailVerification,
	})

	_, _ = p.VerifyEmailOTP(ctx, &emailotp.VerifyEmailOTPParams{
		Email: user.Email,
		OTP:   (*sent)[0].OTP,
	})

	mu.Lock()
	defer mu.Unlock()
	if !receivedSentEvent || !receivedVerifiedEvent {
		t.Fatalf("expected events published to EventBus, got sent=%v, verified=%v", receivedSentEvent, receivedVerifiedEvent)
	}
}
