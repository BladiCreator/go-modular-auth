package magiclink_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/BladiCreator/go-modular-auth/domain/dto"
	"github.com/BladiCreator/go-modular-auth/domain/entity"
	"github.com/BladiCreator/go-modular-auth/domain/repository"
	"github.com/BladiCreator/go-modular-auth/plugin"
	"github.com/BladiCreator/go-modular-auth/plugins/magiclink"
	"uuid"
)

// mockRepository implements magiclink.Repository for unit tests
type mockRepository struct {
	*repository.MemorySessionRepository
	*repository.MemoryVerificationRepository
	mu           sync.Mutex
	users        map[string]*entity.User
	usersByEmail map[string]*entity.User
}

func newMockRepository() *mockRepository {
	return &mockRepository{
		MemorySessionRepository:      repository.NewMemorySessionRepository(),
		MemoryVerificationRepository: repository.NewMemoryVerificationRepository(),
		users:                        make(map[string]*entity.User),
		usersByEmail:                 make(map[string]*entity.User),
	}
}

func (m *mockRepository) GetUserByEmail(ctx context.Context, email string) (*entity.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.usersByEmail[email]
	if !ok {
		return nil, magiclink.ErrUserNotFound
	}
	return u, nil
}

func (m *mockRepository) CreateUser(ctx context.Context, params *dto.CreateUserParams) (*entity.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	user := &entity.User{
		ID:            uuid.NewV7().String(),
		Email:         params.Email,
		Name:          params.Name,
		EmailVerified: false,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}
	m.users[user.ID] = user
	m.usersByEmail[user.Email] = user
	return user, nil
}

func (m *mockRepository) UpdateUser(ctx context.Context, user *entity.User) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.users[user.ID] = user
	m.usersByEmail[user.Email] = user
	return nil
}

func TestMagicLink_FullFlow(t *testing.T) {
	repo := newMockRepository()
	var sentData magiclink.SendMagicLinkData

	p := magiclink.New(repo,
		magiclink.WithSendMagicLink(func(ctx context.Context, data magiclink.SendMagicLinkData) error {
			sentData = data
			return nil
		}),
		magiclink.WithExpiresIn(5*time.Minute),
		magiclink.WithDefaultCallbackURL("/dashboard"),
	)

	ctx := context.Background()

	// 1. Sign In / Send Magic Link for New User
	signInRes, err := p.SignInMagicLink(ctx, magiclink.SignInMagicLinkParams{
		Email:       "testuser@example.com",
		Name:        "Test User",
		CallbackURL: "/dashboard",
	})
	if err != nil {
		t.Fatalf("SignInMagicLink failed: %v", err)
	}
	if !signInRes.Success {
		t.Fatalf("expected success to be true")
	}
	if sentData.Token == "" {
		t.Fatalf("expected token to be set in SendMagicLink callback")
	}

	// 2. Verify Magic Link for New User
	verifyRes, err := p.VerifyMagicLink(ctx, magiclink.VerifyMagicLinkParams{
		Token: sentData.Token,
		Email: sentData.Email,
	})
	if err != nil {
		t.Fatalf("VerifyMagicLink failed: %v", err)
	}
	if !verifyRes.IsNewUser {
		t.Errorf("expected IsNewUser to be true")
	}
	if verifyRes.User.Email != "testuser@example.com" {
		t.Errorf("expected email testuser@example.com, got %s", verifyRes.User.Email)
	}
	if verifyRes.Session == nil {
		t.Errorf("expected session to be created")
	}
	if verifyRes.RedirectURL != "/dashboard" {
		t.Errorf("expected redirect URL /dashboard, got %s", verifyRes.RedirectURL)
	}

	// 3. Verify Replay Protection (Attempting to verify same token a second time)
	_, err = p.VerifyMagicLink(ctx, magiclink.VerifyMagicLinkParams{
		Token: sentData.Token,
		Email: sentData.Email,
	})
	if err == nil {
		t.Fatalf("expected error on 2nd token consumption attempt, got nil")
	}
}

func TestMagicLink_DisableSignUp(t *testing.T) {
	repo := newMockRepository()
	var sentData magiclink.SendMagicLinkData

	p := magiclink.New(repo,
		magiclink.WithSendMagicLink(func(ctx context.Context, data magiclink.SendMagicLinkData) error {
			sentData = data
			return nil
		}),
		magiclink.WithDisableSignUp(true),
	)

	ctx := context.Background()

	_, err := p.SignInMagicLink(ctx, magiclink.SignInMagicLinkParams{
		Email: "nonexistent@example.com",
	})
	if err != nil {
		t.Fatalf("SignInMagicLink unexpectedly failed: %v", err)
	}

	_, err = p.VerifyMagicLink(ctx, magiclink.VerifyMagicLinkParams{
		Token: sentData.Token,
		Email: sentData.Email,
	})
	if err != magiclink.ErrSignUpDisabled {
		t.Fatalf("expected ErrSignUpDisabled, got %v", err)
	}
}

func TestMagicLink_HashedTokenMode(t *testing.T) {
	repo := newMockRepository()
	var sentData magiclink.SendMagicLinkData

	p := magiclink.New(repo,
		magiclink.WithSendMagicLink(func(ctx context.Context, data magiclink.SendMagicLinkData) error {
			sentData = data
			return nil
		}),
		magiclink.WithStoreTokenMode(magiclink.StoreTokenHashed),
	)

	ctx := context.Background()

	_, err := p.SignInMagicLink(ctx, magiclink.SignInMagicLinkParams{
		Email: "hasheduser@example.com",
	})
	if err != nil {
		t.Fatalf("SignInMagicLink failed: %v", err)
	}

	verifyRes, err := p.VerifyMagicLink(ctx, magiclink.VerifyMagicLinkParams{
		Token: sentData.Token,
		Email: sentData.Email,
	})
	if err != nil {
		t.Fatalf("VerifyMagicLink failed in hashed mode: %v", err)
	}
	if verifyRes.User.Email != "hasheduser@example.com" {
		t.Errorf("expected user email hasheduser@example.com")
	}
}

func TestMagicLink_EncryptedTokenMode(t *testing.T) {
	repo := newMockRepository()
	var sentData magiclink.SendMagicLinkData

	p := magiclink.New(repo,
		magiclink.WithSendMagicLink(func(ctx context.Context, data magiclink.SendMagicLinkData) error {
			sentData = data
			return nil
		}),
		magiclink.WithStoreTokenMode(magiclink.StoreTokenEncrypted),
		magiclink.WithSecretKey("super-secret-key-32-bytes-long!!"),
	)

	ctx := context.Background()

	_, err := p.SignInMagicLink(ctx, magiclink.SignInMagicLinkParams{
		Email: "encrypteduser@example.com",
	})
	if err != nil {
		t.Fatalf("SignInMagicLink failed: %v", err)
	}

	verifyRes, err := p.VerifyMagicLink(ctx, magiclink.VerifyMagicLinkParams{
		Token: sentData.Token,
		Email: sentData.Email,
	})
	if err != nil {
		t.Fatalf("VerifyMagicLink failed in encrypted mode: %v", err)
	}
	if verifyRes.User.Email != "encrypteduser@example.com" {
		t.Errorf("expected user email encrypteduser@example.com")
	}
}

func TestMagicLink_TokenExpired(t *testing.T) {
	repo := newMockRepository()
	var sentData magiclink.SendMagicLinkData

	p := magiclink.New(repo,
		magiclink.WithSendMagicLink(func(ctx context.Context, data magiclink.SendMagicLinkData) error {
			sentData = data
			return nil
		}),
		magiclink.WithExpiresIn(-1*time.Minute), // Already expired
	)

	ctx := context.Background()

	_, err := p.SignInMagicLink(ctx, magiclink.SignInMagicLinkParams{
		Email: "expireduser@example.com",
	})
	if err != nil {
		t.Fatalf("SignInMagicLink failed: %v", err)
	}

	_, err = p.VerifyMagicLink(ctx, magiclink.VerifyMagicLinkParams{
		Token: sentData.Token,
		Email: sentData.Email,
	})
	if err != magiclink.ErrTokenExpired {
		t.Fatalf("expected ErrTokenExpired, got %v", err)
	}
}

func TestMagicLink_HTTPHandlers(t *testing.T) {
	repo := newMockRepository()
	var sentData magiclink.SendMagicLinkData

	p := magiclink.New(repo,
		magiclink.WithSendMagicLink(func(ctx context.Context, data magiclink.SendMagicLinkData) error {
			sentData = data
			return nil
		}),
		magiclink.WithDefaultCallbackURL("/dashboard"),
	)

	// 1. POST /sign-in/magic-link
	postBody, _ := json.Marshal(magiclink.SignInMagicLinkParams{
		Email: "httpuser@example.com",
	})
	req := httptest.NewRequest(http.MethodPost, "/sign-in/magic-link", bytes.NewBuffer(postBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	p.ServeSignIn(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d", w.Code)
	}

	// 2. GET /magic-link/verify (Browser Request)
	verifyURL := fmt.Sprintf("/magic-link/verify?token=%s&email=%s&callbackURL=/welcome", sentData.Token, sentData.Email)
	reqVerify := httptest.NewRequest(http.MethodGet, verifyURL, nil)
	wVerify := httptest.NewRecorder()

	p.ServeVerify(wVerify, reqVerify)

	if wVerify.Code != http.StatusFound {
		t.Fatalf("expected HTTP 302 Found redirect, got %d", wVerify.Code)
	}
	if loc := wVerify.Header().Get("Location"); loc != "/welcome" {
		t.Errorf("expected redirect Location /welcome, got %s", loc)
	}
}

func TestMagicLink_Events(t *testing.T) {
	repo := newMockRepository()
	pCtx := plugin.NewContext(nil)

	var sentBefore, sentAfter, verifySuccess bool
	pCtx.Hooks().Subscribe(magiclink.EventMagicLinkSendBefore, func(payload *magiclink.SendMagicLinkPendingPayload) {
		sentBefore = true
	})
	pCtx.Hooks().Subscribe(magiclink.EventMagicLinkSent, func(payload *magiclink.MagicLinkSentPayload) {
		sentAfter = true
	})
	pCtx.Hooks().Subscribe(magiclink.EventMagicLinkSignInSuccess, func(payload *magiclink.SignInSuccessPayload) {
		verifySuccess = true
	})

	var sentData magiclink.SendMagicLinkData
	p := magiclink.New(repo,
		magiclink.WithSendMagicLink(func(ctx context.Context, data magiclink.SendMagicLinkData) error {
			sentData = data
			return nil
		}),
	)

	if err := p.Init(pCtx); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	ctx := context.Background()

	_, err := p.SignInMagicLink(ctx, magiclink.SignInMagicLinkParams{
		Email: "eventuser@example.com",
	})
	if err != nil {
		t.Fatalf("SignInMagicLink failed: %v", err)
	}

	if !sentBefore || !sentAfter {
		t.Errorf("expected send events to be triggered")
	}

	_, err = p.VerifyMagicLink(ctx, magiclink.VerifyMagicLinkParams{
		Token: sentData.Token,
		Email: sentData.Email,
	})
	if err != nil {
		t.Fatalf("VerifyMagicLink failed: %v", err)
	}

	if !verifySuccess {
		t.Errorf("expected signInSuccess event to be triggered")
	}
}
