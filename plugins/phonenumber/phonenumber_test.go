package phonenumber_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/BladiCreator/go-modular-auth/domain/dto"
	"github.com/BladiCreator/go-modular-auth/domain/entity"
	"github.com/BladiCreator/go-modular-auth/plugin"
	"github.com/BladiCreator/go-modular-auth/plugins/phonenumber"
	"github.com/asaskevich/EventBus"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// MockRepository implements phonenumber.Repository in memory with thread safety.
type MockRepository struct {
	mu            sync.RWMutex
	verifications map[string]*phonenumber.VerificationRecord
	users         map[string]*entity.User
	usersByPhone  map[string]*entity.User
	accounts      map[string]*entity.Account // key: userID:provider
	sessions      map[string]*entity.Session
}

func NewMockRepository() *MockRepository {
	return &MockRepository{
		verifications: make(map[string]*phonenumber.VerificationRecord),
		users:         make(map[string]*entity.User),
		usersByPhone:  make(map[string]*entity.User),
		accounts:      make(map[string]*entity.Account),
		sessions:      make(map[string]*entity.Session),
	}
}

func (m *MockRepository) FindVerificationValue(ctx context.Context, identifier string) (*phonenumber.VerificationRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	rec, ok := m.verifications[identifier]
	if !ok {
		return nil, phonenumber.ErrOTPNotFound
	}
	cp := *rec
	return &cp, nil
}

func (m *MockRepository) CreateVerificationValue(ctx context.Context, record *phonenumber.VerificationRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *record
	m.verifications[record.Identifier] = &cp
	return nil
}

func (m *MockRepository) UpdateVerificationValue(ctx context.Context, identifier, value string, expiresAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.verifications[identifier]
	if !ok {
		return phonenumber.ErrOTPNotFound
	}
	rec.Value = value
	rec.ExpiresAt = expiresAt
	rec.UpdatedAt = time.Now()
	return nil
}

func (m *MockRepository) DeleteVerificationValue(ctx context.Context, identifier string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.verifications, identifier)
	return nil
}

func (m *MockRepository) ConsumeVerificationValue(ctx context.Context, identifier string) (*phonenumber.VerificationRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.verifications[identifier]
	if !ok {
		return nil, phonenumber.ErrOTPNotFound
	}
	delete(m.verifications, identifier)
	cp := *rec
	return &cp, nil
}

func (m *MockRepository) GetUserByID(ctx context.Context, userID string) (*entity.User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	u, ok := m.users[userID]
	if !ok {
		return nil, phonenumber.ErrUserNotFound
	}
	cp := *u
	return &cp, nil
}

func (m *MockRepository) GetUserByPhoneNumber(ctx context.Context, phoneNumber string) (*entity.User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	u, ok := m.usersByPhone[phoneNumber]
	if !ok {
		return nil, phonenumber.ErrUserNotFound
	}
	cp := *u
	return &cp, nil
}

func (m *MockRepository) CreateUser(ctx context.Context, params *dto.CreateUserParams) (*entity.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u := &entity.User{
		ID:        uuid.NewString(),
		Name:      params.Name,
		Email:     params.Email,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if phone, ok := params.Extra[phonenumber.ExtraKeyPhoneNumber].(string); ok && phone != "" {
		u.PhoneNumber = &phone
		if verified, ok := params.Extra[phonenumber.ExtraKeyPhoneNumberVerified].(bool); ok {
			u.PhoneNumberVerified = verified
		}
		m.usersByPhone[phone] = u
	}
	m.users[u.ID] = u
	cp := *u
	return &cp, nil
}

func (m *MockRepository) UpdateUser(ctx context.Context, user *entity.User) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	existing, ok := m.users[user.ID]
	if !ok {
		return phonenumber.ErrUserNotFound
	}
	// Clean up old phone index if changed
	if existing.PhoneNumber != nil && (user.PhoneNumber == nil || *existing.PhoneNumber != *user.PhoneNumber) {
		delete(m.usersByPhone, *existing.PhoneNumber)
	}
	cp := *user
	m.users[user.ID] = &cp
	if user.PhoneNumber != nil {
		m.usersByPhone[*user.PhoneNumber] = &cp
	}
	return nil
}

func (m *MockRepository) GetAccountByUserIDAndProvider(ctx context.Context, userID, providerID string) (*entity.Account, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	key := userID + ":" + providerID
	acc, ok := m.accounts[key]
	if !ok {
		return nil, phonenumber.ErrCredentialAccountNotFound
	}
	cp := *acc
	return &cp, nil
}

func (m *MockRepository) CreateAccount(ctx context.Context, account *entity.Account) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := account.UserID + ":" + account.Provider
	cp := *account
	m.accounts[key] = &cp
	return nil
}

func (m *MockRepository) UpdateAccountPassword(ctx context.Context, userID, passwordHash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := userID + ":credential"
	acc, ok := m.accounts[key]
	if !ok {
		return phonenumber.ErrCredentialAccountNotFound
	}
	acc.Password = passwordHash
	acc.UpdatedAt = time.Now()
	return nil
}

func (m *MockRepository) CreateSession(ctx context.Context, params *dto.CreateSessionParams) (*entity.Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	sess := &entity.Session{
		ID:        uuid.NewString(),
		UserID:    params.UserID,
		Token:     params.Token,
		ExpiresAt: params.ExpiresAt,
		CreatedAt: params.CreatedAt,
	}
	m.sessions[sess.ID] = sess
	cp := *sess
	return &cp, nil
}

func (m *MockRepository) DeleteSessionsByUserID(ctx context.Context, userID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, sess := range m.sessions {
		if sess.UserID == userID {
			delete(m.sessions, id)
		}
	}
	return nil
}

// MockCryptoUtils implements plugin.CryptoUtils.
type MockCryptoUtils struct{}

func (c *MockCryptoUtils) HashPassword(password string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	return string(b), err
}

func (c *MockCryptoUtils) ComparePassword(hash, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

func (c *MockCryptoUtils) GenerateRandomToken(length int) (string, error) {
	return uuid.NewString(), nil
}

func setupTestContext(t *testing.T) *plugin.Context {
	bus := EventBus.New()
	crypto := &MockCryptoUtils{}
	return plugin.NewContext(crypto, bus)
}

func TestSendOTP_Success(t *testing.T) {
	repo := NewMockRepository()
	var lastSentCode string
	var lastPhone string

	p := phonenumber.New(repo,
		phonenumber.WithSendOTP(func(ctx context.Context, data phonenumber.SendOTPData) error {
			lastSentCode = data.Code
			lastPhone = data.PhoneNumber
			return nil
		}),
		phonenumber.WithOTPLength(6),
	)
	ctx := setupTestContext(t)
	_ = p.Init(ctx)

	res, err := p.SendOTP(context.Background(), phonenumber.SendOTPParams{
		PhoneNumber: "+1234567890",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Success {
		t.Errorf("expected success to be true")
	}
	if lastPhone != "+1234567890" {
		t.Errorf("expected phone %q, got %q", "+1234567890", lastPhone)
	}
	if len(lastSentCode) != 6 {
		t.Errorf("expected 6 digit OTP, got %q", lastSentCode)
	}
}

func TestSendOTP_InvalidPhoneNumber(t *testing.T) {
	repo := NewMockRepository()
	p := phonenumber.New(repo,
		phonenumber.WithSendOTP(func(ctx context.Context, data phonenumber.SendOTPData) error {
			return nil
		}),
	)
	_, err := p.SendOTP(context.Background(), phonenumber.SendOTPParams{
		PhoneNumber: "",
	})
	if !errors.Is(err, phonenumber.ErrInvalidPhoneNumber) {
		t.Errorf("expected ErrInvalidPhoneNumber, got %v", err)
	}
}

func TestSendOTP_CustomValidator(t *testing.T) {
	repo := NewMockRepository()
	p := phonenumber.New(repo,
		phonenumber.WithSendOTP(func(ctx context.Context, data phonenumber.SendOTPData) error {
			return nil
		}),
		phonenumber.WithPhoneNumberValidator(func(ctx context.Context, phone string) (bool, error) {
			return strings.HasPrefix(phone, "+"), nil
		}),
	)

	_, err := p.SendOTP(context.Background(), phonenumber.SendOTPParams{
		PhoneNumber: "1234567890",
	})
	if !errors.Is(err, phonenumber.ErrInvalidPhoneNumber) {
		t.Errorf("expected ErrInvalidPhoneNumber for un-prefixed phone, got %v", err)
	}

	res, err := p.SendOTP(context.Background(), phonenumber.SendOTPParams{
		PhoneNumber: "+1234567890",
	})
	if err != nil || !res.Success {
		t.Fatalf("expected success with valid prefix, got %v", err)
	}
}

func TestVerify_AutoSignUp_And_ExistingUserSignIn(t *testing.T) {
	repo := NewMockRepository()
	var dispatchedCode string
	p := phonenumber.New(repo,
		phonenumber.WithSendOTP(func(ctx context.Context, data phonenumber.SendOTPData) error {
			dispatchedCode = data.Code
			return nil
		}),
		phonenumber.WithSignUpOnVerification(phonenumber.SignUpOnVerificationConfig{
			GetTempEmail: func(phone string) string { return phone + "@test.org" },
			GetTempName:  func(phone string) string { return "User " + phone },
		}),
	)
	ctx := setupTestContext(t)
	_ = p.Init(ctx)

	phone := "+15550001"
	_, err := p.SendOTP(context.Background(), phonenumber.SendOTPParams{PhoneNumber: phone})
	if err != nil {
		t.Fatalf("SendOTP error: %v", err)
	}

	// 1. First verification: should auto-provision new user
	verifyRes, err := p.Verify(context.Background(), phonenumber.VerifyParams{
		PhoneNumber: phone,
		Code:        dispatchedCode,
	})
	if err != nil {
		t.Fatalf("Verify auto-signup error: %v", err)
	}
	if !verifyRes.Success || verifyRes.User == nil {
		t.Fatalf("expected successful user creation")
	}
	if verifyRes.User.Email != phone+"@test.org" {
		t.Errorf("expected email %s@test.org, got %s", phone, verifyRes.User.Email)
	}
	if !verifyRes.User.PhoneNumberVerified {
		t.Errorf("expected PhoneNumberVerified to be true")
	}
	if verifyRes.SessionToken == "" || verifyRes.Session == nil {
		t.Errorf("expected active session to be created")
	}

	// 2. Second verification: existing user sign-in
	_, _ = p.SendOTP(context.Background(), phonenumber.SendOTPParams{PhoneNumber: phone})
	verifyRes2, err := p.Verify(context.Background(), phonenumber.VerifyParams{
		PhoneNumber: phone,
		Code:        dispatchedCode,
	})
	if err != nil {
		t.Fatalf("Verify existing user error: %v", err)
	}
	if verifyRes2.User.ID != verifyRes.User.ID {
		t.Errorf("expected same user ID %s, got %s", verifyRes.User.ID, verifyRes2.User.ID)
	}
}

func TestVerify_UpdatePhoneNumber(t *testing.T) {
	repo := NewMockRepository()
	ctx := setupTestContext(t)

	// Pre-create user without phone
	user, _ := repo.CreateUser(context.Background(), &dto.CreateUserParams{
		Email: "existing@example.com",
		Name:  "Existing User",
	})

	var sentCode string
	p := phonenumber.New(repo,
		phonenumber.WithSendOTP(func(ctx context.Context, data phonenumber.SendOTPData) error {
			sentCode = data.Code
			return nil
		}),
	)
	_ = p.Init(ctx)

	newPhone := "+1999888777"
	_, _ = p.SendOTP(context.Background(), phonenumber.SendOTPParams{PhoneNumber: newPhone})

	res, err := p.Verify(context.Background(), phonenumber.VerifyParams{
		PhoneNumber:       newPhone,
		Code:              sentCode,
		UserID:            user.ID,
		UpdatePhoneNumber: true,
	})
	if err != nil {
		t.Fatalf("Verify update phone error: %v", err)
	}
	if !res.Success || res.User.PhoneNumber == nil || *res.User.PhoneNumber != newPhone {
		t.Errorf("expected updated phone %q, got %v", newPhone, res.User.PhoneNumber)
	}
	if !res.User.PhoneNumberVerified {
		t.Errorf("expected PhoneNumberVerified = true")
	}
}

func TestVerify_AttemptBudget(t *testing.T) {
	repo := NewMockRepository()
	var realCode string
	p := phonenumber.New(repo,
		phonenumber.WithSendOTP(func(ctx context.Context, data phonenumber.SendOTPData) error {
			realCode = data.Code
			return nil
		}),
		phonenumber.WithAllowedAttempts(3),
	)
	ctx := setupTestContext(t)
	_ = p.Init(ctx)

	phone := "+123456789"
	_, _ = p.SendOTP(context.Background(), phonenumber.SendOTPParams{PhoneNumber: phone})

	// Attempt 1: Invalid code
	_, err := p.Verify(context.Background(), phonenumber.VerifyParams{PhoneNumber: phone, Code: "000000"})
	if !errors.Is(err, phonenumber.ErrInvalidOTP) {
		t.Fatalf("attempt 1: expected ErrInvalidOTP, got %v", err)
	}

	// Attempt 2: Invalid code
	_, err = p.Verify(context.Background(), phonenumber.VerifyParams{PhoneNumber: phone, Code: "000000"})
	if !errors.Is(err, phonenumber.ErrInvalidOTP) {
		t.Fatalf("attempt 2: expected ErrInvalidOTP, got %v", err)
	}

	// Attempt 3: Invalid code (exhausts budget)
	_, err = p.Verify(context.Background(), phonenumber.VerifyParams{PhoneNumber: phone, Code: "000000"})
	if !errors.Is(err, phonenumber.ErrTooManyAttempts) {
		t.Fatalf("attempt 3: expected ErrTooManyAttempts, got %v", err)
	}

	// Attempt 4 with REAL code should now fail because OTP record was pruned
	_, err = p.Verify(context.Background(), phonenumber.VerifyParams{PhoneNumber: phone, Code: realCode})
	if !errors.Is(err, phonenumber.ErrOTPNotFound) && !errors.Is(err, phonenumber.ErrInvalidOTP) {
		t.Fatalf("attempt 4: expected record to be gone, got %v", err)
	}
}

func TestVerify_AntiReplay_RaceCondition(t *testing.T) {
	repo := NewMockRepository()
	var realCode string
	p := phonenumber.New(repo,
		phonenumber.WithSendOTP(func(ctx context.Context, data phonenumber.SendOTPData) error {
			realCode = data.Code
			return nil
		}),
	)
	ctx := setupTestContext(t)
	_ = p.Init(ctx)

	phone := "+111222333"
	_, _ = p.SendOTP(context.Background(), phonenumber.SendOTPParams{PhoneNumber: phone})

	const goroutines = 10
	var wg sync.WaitGroup
	var successCount int
	var mu sync.Mutex

	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			res, err := p.Verify(context.Background(), phonenumber.VerifyParams{
				PhoneNumber: phone,
				Code:        realCode,
			})
			if err == nil && res.Success {
				mu.Lock()
				successCount++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if successCount != 1 {
		t.Errorf("expected strictly 1 successful atomic verification, got %d", successCount)
	}
}

func TestSignIn_PhonePassword_And_RequireVerification(t *testing.T) {
	repo := NewMockRepository()
	ctx := setupTestContext(t)

	p := phonenumber.New(repo,
		phonenumber.WithSendOTP(func(ctx context.Context, data phonenumber.SendOTPData) error {
			return nil
		}),
		phonenumber.WithRequireVerification(true),
	)
	_ = p.Init(ctx)

	phone := "+1444555666"
	password := "SecretPass123!"
	hashed, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)

	// User not verified initially
	user, _ := repo.CreateUser(context.Background(), &dto.CreateUserParams{
		Email: "phoneuser@example.com",
		Name:  "Phone User",
		ExtraContainer: plugin.ExtraContainer{
			Extra: map[string]any{
				phonenumber.ExtraKeyPhoneNumber:         phone,
				phonenumber.ExtraKeyPhoneNumberVerified: false,
			},
		},
	})
	_ = repo.CreateAccount(context.Background(), &entity.Account{
		ID:       uuid.NewString(),
		UserID:   user.ID,
		Provider: "credential",
		Password: string(hashed),
	})

	// 1. Should fail with ErrPhoneNumberNotVerified when RequireVerification is true
	_, err := p.SignIn(context.Background(), phonenumber.SignInParams{
		PhoneNumber: phone,
		Password:    password,
	})
	if !errors.Is(err, phonenumber.ErrPhoneNumberNotVerified) {
		t.Fatalf("expected ErrPhoneNumberNotVerified, got %v", err)
	}

	// 2. Mark phone verified
	user.PhoneNumberVerified = true
	_ = repo.UpdateUser(context.Background(), user)

	// 3. Now sign in should succeed
	signInRes, err := p.SignIn(context.Background(), phonenumber.SignInParams{
		PhoneNumber: phone,
		Password:    password,
	})
	if err != nil {
		t.Fatalf("expected sign in success, got %v", err)
	}
	if signInRes.User.ID != user.ID || signInRes.SessionToken == "" {
		t.Errorf("invalid sign in result: %+v", signInRes)
	}

	// 4. Invalid password should fail
	_, err = p.SignIn(context.Background(), phonenumber.SignInParams{
		PhoneNumber: phone,
		Password:    "WrongPassword",
	})
	if !errors.Is(err, phonenumber.ErrInvalidPhoneNumberOrPassword) {
		t.Errorf("expected ErrInvalidPhoneNumberOrPassword, got %v", err)
	}
}

func TestPasswordReset_Flow(t *testing.T) {
	repo := NewMockRepository()
	ctx := setupTestContext(t)

	var resetCode string
	p := phonenumber.New(repo,
		phonenumber.WithSendOTP(func(ctx context.Context, data phonenumber.SendOTPData) error {
			resetCode = data.Code
			return nil
		}),
		phonenumber.WithRevokeSessionsOnPasswordReset(true),
	)
	_ = p.Init(ctx)

	phone := "+1777888999"
	user, _ := repo.CreateUser(context.Background(), &dto.CreateUserParams{
		Email: "resetuser@example.com",
		Name:  "Reset User",
		ExtraContainer: plugin.ExtraContainer{
			Extra: map[string]any{
				phonenumber.ExtraKeyPhoneNumber:         phone,
				phonenumber.ExtraKeyPhoneNumberVerified: true,
			},
		},
	})
	// Create active session
	_, _ = repo.CreateSession(context.Background(), &dto.CreateSessionParams{
		UserID: user.ID,
		Token:  "active-token",
	})

	// 1. Request Reset
	reqRes, err := p.RequestPasswordReset(context.Background(), phonenumber.RequestPasswordResetParams{
		PhoneNumber: phone,
	})
	if err != nil || !reqRes.Success {
		t.Fatalf("RequestPasswordReset failed: %v", err)
	}
	if resetCode == "" {
		t.Fatalf("expected reset code to be generated")
	}

	// 2. Confirm Reset
	newPass := "NewSecurePassword456!"
	resetRes, err := p.ResetPassword(context.Background(), phonenumber.ResetPasswordParams{
		PhoneNumber: phone,
		OTP:         resetCode,
		NewPassword: newPass,
	})
	if err != nil || !resetRes.Success {
		t.Fatalf("ResetPassword failed: %v", err)
	}

	// 3. Verify that old session was revoked
	if len(repo.sessions) != 0 {
		t.Errorf("expected all sessions to be revoked on password reset, found %d", len(repo.sessions))
	}

	// 4. Test Sign In with new password
	signInRes, err := p.SignIn(context.Background(), phonenumber.SignInParams{
		PhoneNumber: phone,
		Password:    newPass,
	})
	if err != nil || signInRes.User.ID != user.ID {
		t.Fatalf("Sign in with new password failed: %v", err)
	}
}

func TestUnlinkPhoneNumber(t *testing.T) {
	repo := NewMockRepository()
	ctx := setupTestContext(t)

	phone := "+1333444555"
	user, _ := repo.CreateUser(context.Background(), &dto.CreateUserParams{
		Email: "unlink@example.com",
		Name:  "Unlink User",
		ExtraContainer: plugin.ExtraContainer{
			Extra: map[string]any{
				phonenumber.ExtraKeyPhoneNumber:         phone,
				phonenumber.ExtraKeyPhoneNumberVerified: true,
			},
		},
	})

	p := phonenumber.New(repo)
	_ = p.Init(ctx)

	unlinkedUser, err := p.UnlinkPhoneNumber(context.Background(), user.ID)
	if err != nil {
		t.Fatalf("UnlinkPhoneNumber failed: %v", err)
	}
	if unlinkedUser.PhoneNumber != nil || unlinkedUser.PhoneNumberVerified {
		t.Errorf("expected PhoneNumber to be nil and verified = false")
	}

	// Verify in repo
	fromRepo, _ := repo.GetUserByID(context.Background(), user.ID)
	if fromRepo.PhoneNumber != nil || fromRepo.PhoneNumberVerified {
		t.Errorf("repository state not updated on unlink")
	}
}

func TestStorageModes_Plain_Hashed_Encrypted(t *testing.T) {
	repo := NewMockRepository()
	ctx := setupTestContext(t)

	modes := []struct {
		name      string
		mode      phonenumber.StoreOTPMode
		secretKey string
	}{
		{"Plain", phonenumber.StoreOTPPlain, ""},
		{"Hashed", phonenumber.StoreOTPHashed, ""},
		{"Encrypted", phonenumber.StoreOTPEncrypted, "my-super-secret-key-for-aes-256"},
	}

	for _, tc := range modes {
		t.Run(tc.name, func(t *testing.T) {
			var code string
			opts := []phonenumber.Option{
				phonenumber.WithSendOTP(func(ctx context.Context, data phonenumber.SendOTPData) error {
					code = data.Code
					return nil
				}),
				phonenumber.WithStoreOTP(tc.mode, tc.secretKey),
			}
			p := phonenumber.New(repo, opts...)
			_ = p.Init(ctx)

			phone := fmt.Sprintf("+10000000%d", time.Now().UnixNano()%1000)
			_, err := p.SendOTP(context.Background(), phonenumber.SendOTPParams{PhoneNumber: phone})
			if err != nil {
				t.Fatalf("SendOTP failed: %v", err)
			}

			// Verify CheckVerificationOTP works
			checkRes, err := p.CheckVerificationOTP(context.Background(), phonenumber.CheckVerificationOTPParams{
				PhoneNumber: phone,
				Type:        phonenumber.OTPTypeVerification,
				OTP:         code,
			})
			if err != nil || !checkRes.Success {
				t.Fatalf("CheckVerificationOTP failed: %v", err)
			}

			// Verify consumption
			vRes, err := p.Verify(context.Background(), phonenumber.VerifyParams{
				PhoneNumber: phone,
				Code:        code,
			})
			if err != nil || !vRes.Success {
				t.Fatalf("Verify failed: %v", err)
			}
		})
	}
}

func TestServerUtilities_Create_Get_Check(t *testing.T) {
	repo := NewMockRepository()
	ctx := setupTestContext(t)

	p := phonenumber.New(repo, phonenumber.WithStoreOTP(phonenumber.StoreOTPPlain))
	_ = p.Init(ctx)

	phone := "+1888123456"
	createRes, err := p.CreateVerificationOTP(context.Background(), phonenumber.CreateVerificationOTPParams{
		PhoneNumber: phone,
		Type:        phonenumber.OTPTypeVerification,
	})
	if err != nil || !createRes.Success {
		t.Fatalf("CreateVerificationOTP failed: %v", err)
	}

	getRes, err := p.GetVerificationOTP(context.Background(), phonenumber.GetVerificationOTPParams{
		PhoneNumber: phone,
		Type:        phonenumber.OTPTypeVerification,
	})
	if err != nil || getRes.OTP == "" {
		t.Fatalf("GetVerificationOTP failed: %v", err)
	}

	checkRes, err := p.CheckVerificationOTP(context.Background(), phonenumber.CheckVerificationOTPParams{
		PhoneNumber: phone,
		Type:        phonenumber.OTPTypeVerification,
		OTP:         getRes.OTP,
	})
	if err != nil || !checkRes.Success {
		t.Fatalf("CheckVerificationOTP failed: %v", err)
	}
}
