package ott_test

import (
	"context"
	"errors"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/BladiCreator/go-modular-auth/domain/dto"
	"github.com/BladiCreator/go-modular-auth/domain/entity"
	"github.com/BladiCreator/go-modular-auth/domain/repository"
	"github.com/BladiCreator/go-modular-auth/plugin"
	"github.com/BladiCreator/go-modular-auth/plugins/ott"
	"github.com/asaskevich/EventBus"
)

type mockRepository struct {
	*repository.MemorySessionRepository
	mu                  sync.RWMutex
	verificationRecords map[string]*ott.VerificationRecord
	users               map[string]*entity.User
}

func newMockRepository() *mockRepository {
	return &mockRepository{
		MemorySessionRepository: repository.NewMemorySessionRepository(),
		verificationRecords:     make(map[string]*ott.VerificationRecord),
		users:                   make(map[string]*entity.User),
	}
}

func (m *mockRepository) CreateVerificationValue(ctx context.Context, record *ott.VerificationRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.verificationRecords[record.Identifier] = record
	return nil
}

func (m *mockRepository) ConsumeVerificationValue(ctx context.Context, identifier string) (*ott.VerificationRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, exists := m.verificationRecords[identifier]
	if !exists {
		return nil, ott.ErrInvalidToken
	}
	delete(m.verificationRecords, identifier)
	return rec, nil
}

func (m *mockRepository) GetUserByID(ctx context.Context, userID string) (*entity.User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	user, exists := m.users[userID]
	if !exists {
		return nil, ott.ErrUserNotFound
	}
	return user, nil
}

func setupTest(t *testing.T) (*mockRepository, *entity.User, *entity.Session) {
	repo := newMockRepository()
	user := &entity.User{
		ID:        "user_123",
		Email:     "test@example.com",
		Name:      "Test User",
		CreatedAt: time.Now(),
	}
	repo.users[user.ID] = user

	session, err := repo.CreateSession(context.Background(), &dto.CreateSessionParams{
		UserID:    user.ID,
		Token:     "session_token_xyz",
		ExpiresAt: time.Now().Add(1 * time.Hour),
		CreatedAt: time.Now(),
	})
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	return repo, user, session
}

func TestOTT_BasicFlow(t *testing.T) {
	repo, user, session := setupTest(t)
	p := ott.New(repo)

	ctx := context.Background()

	// 1. Generate Token
	genRes, err := p.GenerateToken(ctx, ott.GenerateTokenParams{
		SessionToken: session.Token,
		IsClientReq:  false,
	})
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}
	if genRes.Token == "" {
		t.Fatal("expected non-empty token")
	}

	// 2. Verify Token (first attempt - should succeed)
	verRes, err := p.VerifyToken(ctx, ott.VerifyTokenParams{
		Token: genRes.Token,
	})
	if err != nil {
		t.Fatalf("VerifyToken failed: %v", err)
	}
	if verRes.User.ID != user.ID {
		t.Errorf("expected user ID %s, got %s", user.ID, verRes.User.ID)
	}
	if verRes.Session.ID != session.ID {
		t.Errorf("expected session ID %s, got %s", session.ID, verRes.Session.ID)
	}

	// 3. Re-verify Token (second attempt - MUST fail due to single-use consumption)
	_, err = p.VerifyToken(ctx, ott.VerifyTokenParams{
		Token: genRes.Token,
	})
	if !errors.Is(err, ott.ErrInvalidToken) {
		t.Errorf("expected ErrInvalidToken on second verify attempt, got %v", err)
	}
}

func TestOTT_TokenExpired(t *testing.T) {
	repo, _, session := setupTest(t)
	p := ott.New(repo, ott.WithExpiresIn(50*time.Millisecond))

	ctx := context.Background()

	genRes, err := p.GenerateToken(ctx, ott.GenerateTokenParams{
		SessionToken: session.Token,
	})
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}

	time.Sleep(100 * time.Millisecond)

	_, err = p.VerifyToken(ctx, ott.VerifyTokenParams{
		Token: genRes.Token,
	})
	if !errors.Is(err, ott.ErrTokenExpired) {
		t.Errorf("expected ErrTokenExpired, got %v", err)
	}
}

func TestOTT_SessionExpiredOrNotFound(t *testing.T) {
	repo, _, _ := setupTest(t)

	// Session expired
	expiredSess, _ := repo.CreateSession(context.Background(), &dto.CreateSessionParams{
		UserID:    "user_123",
		Token:     "token_expired",
		ExpiresAt: time.Now().Add(-1 * time.Minute),
		CreatedAt: time.Now().Add(-1 * time.Hour),
	})

	p := ott.New(repo)
	ctx := context.Background()

	_, err := p.GenerateToken(ctx, ott.GenerateTokenParams{
		SessionToken: expiredSess.Token,
	})
	if !errors.Is(err, ott.ErrSessionExpired) {
		t.Errorf("expected ErrSessionExpired during generation, got %v", err)
	}

	// Non-existent session
	_, err = p.GenerateToken(ctx, ott.GenerateTokenParams{
		SessionToken: "non_existent_token",
	})
	if !errors.Is(err, ott.ErrSessionNotFound) {
		t.Errorf("expected ErrSessionNotFound, got %v", err)
	}
}

func TestOTT_StoreTokenModeHashed(t *testing.T) {
	repo, user, session := setupTest(t)
	p := ott.New(repo, ott.WithStoreTokenMode(ott.StoreTokenHashed))

	ctx := context.Background()

	genRes, err := p.GenerateToken(ctx, ott.GenerateTokenParams{
		SessionToken: session.Token,
	})
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}

	// Raw token must not match stored key directly
	hashedKey, err := ott.DefaultTokenHasher(genRes.Token)
	if err != nil {
		t.Fatalf("DefaultTokenHasher failed: %v", err)
	}

	rawIdentifier := ott.ToOTTIdentifier(genRes.Token)
	hashedIdentifier := ott.ToOTTIdentifier(hashedKey)

	repo.mu.RLock()
	_, rawFound := repo.verificationRecords[rawIdentifier]
	_, hashedFound := repo.verificationRecords[hashedIdentifier]
	repo.mu.RUnlock()

	if rawFound {
		t.Error("expected raw token NOT to be found directly in repository when mode is hashed")
	}
	if !hashedFound {
		t.Error("expected hashed token key to be stored in repository")
	}

	// Verification using raw token must succeed
	verRes, err := p.VerifyToken(ctx, ott.VerifyTokenParams{
		Token: genRes.Token,
	})
	if err != nil {
		t.Fatalf("VerifyToken with hashed mode failed: %v", err)
	}
	if verRes.User.ID != user.ID {
		t.Errorf("expected user ID %s, got %s", user.ID, verRes.User.ID)
	}
}

func TestOTT_CustomHasherAndGenerator(t *testing.T) {
	repo, _, session := setupTest(t)

	customGenCalled := false
	customHashCalled := false

	p := ott.New(
		repo,
		ott.WithStoreTokenMode(ott.StoreTokenHashed),
		ott.WithCustomGenerator(func(length int) (string, error) {
			customGenCalled = true
			return "custom_ott_token_1234567890", nil
		}),
		ott.WithCustomHasher(func(token string) (string, error) {
			customHashCalled = true
			return "hashed_" + token, nil
		}),
	)

	ctx := context.Background()

	genRes, err := p.GenerateToken(ctx, ott.GenerateTokenParams{
		SessionToken: session.Token,
	})
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}
	if !customGenCalled {
		t.Error("expected custom generator to be called")
	}
	if genRes.Token != "custom_ott_token_1234567890" {
		t.Errorf("expected custom generated token, got %s", genRes.Token)
	}

	_, err = p.VerifyToken(ctx, ott.VerifyTokenParams{
		Token: genRes.Token,
	})
	if err != nil {
		t.Fatalf("VerifyToken failed: %v", err)
	}
	if !customHashCalled {
		t.Error("expected custom hasher to be called")
	}
}

func TestOTT_DisableClientRequest(t *testing.T) {
	repo, _, session := setupTest(t)
	p := ott.New(repo, ott.WithDisableClientRequest(true))

	ctx := context.Background()

	// Client request should be rejected
	_, err := p.GenerateToken(ctx, ott.GenerateTokenParams{
		SessionToken: session.Token,
		IsClientReq:  true,
	})
	if !errors.Is(err, ott.ErrClientRequestDisabled) {
		t.Errorf("expected ErrClientRequestDisabled, got %v", err)
	}

	// Server request should succeed
	genRes, err := p.GenerateToken(ctx, ott.GenerateTokenParams{
		SessionToken: session.Token,
		IsClientReq:  false,
	})
	if err != nil {
		t.Fatalf("GenerateToken for server request failed: %v", err)
	}
	if genRes.Token == "" {
		t.Error("expected valid token")
	}
}

func TestOTT_AttachHeader(t *testing.T) {
	repo, _, session := setupTest(t)
	p := ott.New(repo, ott.WithSetOttHeaderOnNewSession(true))

	rec := httptest.NewRecorder()
	err := p.AttachHeader(rec, session.Token)
	if err != nil {
		t.Fatalf("AttachHeader failed: %v", err)
	}

	ottHeader := rec.Header().Get("set-ott")
	if ottHeader == "" {
		t.Error("expected set-ott response header to be set")
	}

	exposeHeader := rec.Header().Get("Access-Control-Expose-Headers")
	if exposeHeader != "set-ott" {
		t.Errorf("expected Access-Control-Expose-Headers to contain 'set-ott', got %s", exposeHeader)
	}
}

func TestOTT_EventBus(t *testing.T) {
	repo, _, session := setupTest(t)
	bus := EventBus.New()
	pCtx := plugin.NewContext(nil, bus)

	p := ott.New(repo)
	if err := p.Init(pCtx); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	var generatedEvent *ott.OTTGeneratedPayload
	var verifiedEvent *ott.OTTVerifiedPayload

	bus.Subscribe(ott.EventOTTGenerated, func(ctx context.Context, payload *ott.OTTGeneratedPayload) {
		generatedEvent = payload
	})
	bus.Subscribe(ott.EventOTTVerified, func(ctx context.Context, payload *ott.OTTVerifiedPayload) {
		verifiedEvent = payload
	})

	ctx := context.Background()

	genRes, err := p.GenerateToken(ctx, ott.GenerateTokenParams{
		SessionToken: session.Token,
	})
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}
	if generatedEvent == nil || generatedEvent.Token != genRes.Token {
		t.Errorf("expected EventOTTGenerated with token %s, got %v", genRes.Token, generatedEvent)
	}

	_, err = p.VerifyToken(ctx, ott.VerifyTokenParams{
		Token: genRes.Token,
	})
	if err != nil {
		t.Fatalf("VerifyToken failed: %v", err)
	}
	if verifiedEvent == nil || verifiedEvent.Token != genRes.Token {
		t.Errorf("expected EventOTTVerified with token %s, got %v", genRes.Token, verifiedEvent)
	}
}
