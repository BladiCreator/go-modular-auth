package deviceauth_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/BladiCreator/go-modular-auth/domain/entity"
	"github.com/BladiCreator/go-modular-auth/plugin"
	"github.com/BladiCreator/go-modular-auth/plugins/deviceauth"
)

// MockRepository implements deviceauth.Repository for testing purposes.
type MockRepository struct {
	mu          sync.Mutex
	codesByDev  map[string]*deviceauth.DeviceCode
	codesByUser map[string]*deviceauth.DeviceCode
	users       map[string]*entity.User
	sessions    map[string]*entity.Session
}

func NewMockRepository() *MockRepository {
	return &MockRepository{
		codesByDev:  make(map[string]*deviceauth.DeviceCode),
		codesByUser: make(map[string]*deviceauth.DeviceCode),
		users:       make(map[string]*entity.User),
		sessions:    make(map[string]*entity.Session),
	}
}

func (m *MockRepository) CreateDeviceCode(ctx context.Context, code *deviceauth.DeviceCode) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	cp := *code
	m.codesByDev[code.DeviceCode] = &cp
	m.codesByUser[code.UserCode] = &cp
	return nil
}

func (m *MockRepository) FindByDeviceCode(ctx context.Context, devCode string) (*deviceauth.DeviceCode, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	code, ok := m.codesByDev[devCode]
	if !ok {
		return nil, deviceauth.ErrInvalidDeviceCode
	}
	cp := *code
	return &cp, nil
}

func (m *MockRepository) FindByUserCode(ctx context.Context, usrCode string) (*deviceauth.DeviceCode, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	code, ok := m.codesByUser[usrCode]
	if !ok {
		return nil, deviceauth.ErrInvalidUserCode
	}
	cp := *code
	return &cp, nil
}

func (m *MockRepository) UpdateLastPolledAt(ctx context.Context, devCode string, polledAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	code, ok := m.codesByDev[devCode]
	if !ok {
		return deviceauth.ErrInvalidDeviceCode
	}
	code.LastPolledAt = &polledAt
	code.UpdatedAt = time.Now()
	return nil
}

func (m *MockRepository) UpdateStatus(ctx context.Context, usrCode string, status deviceauth.DeviceCodeStatus, userID *string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	code, ok := m.codesByUser[usrCode]
	if !ok {
		return deviceauth.ErrInvalidUserCode
	}
	code.Status = status
	if userID != nil {
		code.UserID = userID
	}
	code.UpdatedAt = time.Now()
	return nil
}

func (m *MockRepository) ConsumeDeviceCode(ctx context.Context, devCode string) (*deviceauth.DeviceCode, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	code, ok := m.codesByDev[devCode]
	if !ok {
		return nil, deviceauth.ErrAlreadyConsumed
	}

	if code.Status != deviceauth.StatusApproved {
		return nil, deviceauth.ErrAlreadyConsumed
	}

	cp := *code
	delete(m.codesByDev, devCode)
	delete(m.codesByUser, code.UserCode)
	return &cp, nil
}

func (m *MockRepository) DeleteDeviceCode(ctx context.Context, devCode string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if code, ok := m.codesByDev[devCode]; ok {
		delete(m.codesByUser, code.UserCode)
		delete(m.codesByDev, devCode)
	}
	return nil
}

func (m *MockRepository) DeleteExpiredDeviceCodes(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	for devCode, code := range m.codesByDev {
		if code.ExpiresAt.Before(now) {
			delete(m.codesByUser, code.UserCode)
			delete(m.codesByDev, devCode)
		}
	}
	return nil
}

func (m *MockRepository) GetUserByID(ctx context.Context, userID string) (*entity.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	u, ok := m.users[userID]
	if !ok {
		return nil, deviceauth.ErrUserNotFound
	}
	cp := *u
	return &cp, nil
}

func (m *MockRepository) CreateSession(ctx context.Context, session *entity.Session) (*entity.Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	cp := *session
	m.sessions[session.Token] = &cp
	return &cp, nil
}

// -----------------------------------------------------------------------------
// Unit Tests
// -----------------------------------------------------------------------------

func TestUtils_GenerateUserCode(t *testing.T) {
	code, err := deviceauth.DefaultGenerateUserCode(8)
	if err != nil {
		t.Fatalf("unexpected error generating user code: %v", err)
	}

	normalized := deviceauth.NormalizeUserCode(code)
	if len(normalized) != 8 {
		t.Errorf("expected normalized code length 8, got %d (%s)", len(normalized), normalized)
	}

	for _, ch := range normalized {
		if !strings.ContainsRune(deviceauth.DefaultCharset, ch) {
			t.Errorf("user code character %c not in DefaultCharset", ch)
		}
	}
}

func TestUtils_NormalizeUserCode(t *testing.T) {
	cases := []struct {
		input    string
		expected string
	}{
		{"abcd-1234", "ABCD1234"},
		{"  XY 99 - z  ", "XY99Z"},
		{"WXYZ-2345", "WXYZ2345"},
	}

	for _, c := range cases {
		got := deviceauth.NormalizeUserCode(c.input)
		if got != c.expected {
			t.Errorf("NormalizeUserCode(%q) = %q; expected %q", c.input, got, c.expected)
		}
	}
}

func TestUtils_BuildVerificationURIs(t *testing.T) {
	uri, uriComplete := deviceauth.BuildVerificationURIs("/device", "https://auth.example.com", "ABCD-1234")

	if uri != "https://auth.example.com" {
		t.Errorf("expected uri 'https://auth.example.com', got %q", uri)
	}

	if !strings.Contains(uriComplete, "user_code=ABCD-1234") {
		t.Errorf("expected uriComplete to contain 'user_code=ABCD-1234', got %q", uriComplete)
	}
}

// -----------------------------------------------------------------------------
// Integration / Flow Tests
// -----------------------------------------------------------------------------

func TestDeviceAuth_HappyPath(t *testing.T) {
	ctx := context.Background()
	repo := NewMockRepository()

	testUser := &entity.User{
		ID:    "usr_123",
		Name:  "Test Gopher",
		Email: "gopher@golang.org",
	}
	repo.users[testUser.ID] = testUser

	p := deviceauth.New(repo,
		deviceauth.WithExpiresIn(10*time.Minute),
		deviceauth.WithInterval(100*time.Millisecond),
	)
	_ = p.Init(plugin.NewContext(nil, nil))

	// 1. Request device code
	res, err := p.RequestDeviceCode(ctx, deviceauth.RequestDeviceCodeParams{
		ClientID: "cli_app",
	})
	if err != nil {
		t.Fatalf("RequestDeviceCode failed: %v", err)
	}

	if res.DeviceCode == "" || res.UserCode == "" {
		t.Fatalf("expected non-empty codes in response")
	}

	// 2. Poll initial token before user approval -> Pending
	_, err = p.ExchangeDeviceToken(ctx, deviceauth.ExchangeDeviceTokenParams{
		GrantType:  deviceauth.OAuth2DeviceGrantType,
		DeviceCode: res.DeviceCode,
	})
	if !errors.Is(err, deviceauth.ErrAuthorizationPending) {
		t.Fatalf("expected ErrAuthorizationPending, got: %v", err)
	}

	// 3. User checks status -> Pending
	state, err := p.GetVerificationState(ctx, res.UserCode)
	if err != nil {
		t.Fatalf("GetVerificationState failed: %v", err)
	}
	if state.Status != deviceauth.StatusPending {
		t.Fatalf("expected StatusPending, got %s", state.Status)
	}

	// 4. User approves code
	err = p.ApproveDeviceCode(ctx, deviceauth.ApproveDeviceCodeParams{
		UserID:   testUser.ID,
		UserCode: res.UserCode,
	})
	if err != nil {
		t.Fatalf("ApproveDeviceCode failed: %v", err)
	}

	// Sleep to pass polling interval
	time.Sleep(150 * time.Millisecond)

	// 5. Poll again -> Receives AccessToken
	tokenRes, err := p.ExchangeDeviceToken(ctx, deviceauth.ExchangeDeviceTokenParams{
		GrantType:  deviceauth.OAuth2DeviceGrantType,
		DeviceCode: res.DeviceCode,
	})
	if err != nil {
		t.Fatalf("ExchangeDeviceToken failed after approval: %v", err)
	}

	if tokenRes.AccessToken == "" || tokenRes.UserID != testUser.ID {
		t.Errorf("unexpected token response: %+v", tokenRes)
	}

	// 6. Submitting poll again -> Already Consumed
	_, err = p.ExchangeDeviceToken(ctx, deviceauth.ExchangeDeviceTokenParams{
		GrantType:  deviceauth.OAuth2DeviceGrantType,
		DeviceCode: res.DeviceCode,
	})
	if !errors.Is(err, deviceauth.ErrAlreadyConsumed) && !errors.Is(err, deviceauth.ErrInvalidDeviceCode) {
		t.Fatalf("expected ErrAlreadyConsumed or ErrInvalidDeviceCode, got %v", err)
	}
}

func TestDeviceAuth_DenyFlow(t *testing.T) {
	ctx := context.Background()
	repo := NewMockRepository()

	p := deviceauth.New(repo, deviceauth.WithInterval(10*time.Millisecond))
	_ = p.Init(plugin.NewContext(nil, nil))

	res, err := p.RequestDeviceCode(ctx, deviceauth.RequestDeviceCodeParams{ClientID: "cli_app"})
	if err != nil {
		t.Fatalf("RequestDeviceCode failed: %v", err)
	}

	// User denies request
	if err := p.DenyDeviceCode(ctx, deviceauth.DenyDeviceCodeParams{UserCode: res.UserCode}); err != nil {
		t.Fatalf("DenyDeviceCode failed: %v", err)
	}

	time.Sleep(20 * time.Millisecond)

	// Polling token after denial
	_, err = p.ExchangeDeviceToken(ctx, deviceauth.ExchangeDeviceTokenParams{
		GrantType:  deviceauth.OAuth2DeviceGrantType,
		DeviceCode: res.DeviceCode,
	})
	if !errors.Is(err, deviceauth.ErrAccessDenied) {
		t.Fatalf("expected ErrAccessDenied, got: %v", err)
	}
}

func TestDeviceAuth_RateLimiting(t *testing.T) {
	ctx := context.Background()
	repo := NewMockRepository()

	p := deviceauth.New(repo, deviceauth.WithInterval(500*time.Millisecond))
	_ = p.Init(plugin.NewContext(nil, nil))

	res, err := p.RequestDeviceCode(ctx, deviceauth.RequestDeviceCodeParams{ClientID: "cli_app"})
	if err != nil {
		t.Fatalf("RequestDeviceCode failed: %v", err)
	}

	// Poll 1: Pending
	_, err = p.ExchangeDeviceToken(ctx, deviceauth.ExchangeDeviceTokenParams{
		GrantType:  deviceauth.OAuth2DeviceGrantType,
		DeviceCode: res.DeviceCode,
	})
	if !errors.Is(err, deviceauth.ErrAuthorizationPending) {
		t.Fatalf("expected ErrAuthorizationPending, got: %v", err)
	}

	// Poll 2 immediately (< 500ms) -> SlowDown
	_, err = p.ExchangeDeviceToken(ctx, deviceauth.ExchangeDeviceTokenParams{
		GrantType:  deviceauth.OAuth2DeviceGrantType,
		DeviceCode: res.DeviceCode,
	})
	if !errors.Is(err, deviceauth.ErrSlowDown) {
		t.Fatalf("expected ErrSlowDown, got: %v", err)
	}
}

func TestDeviceAuth_Expiration(t *testing.T) {
	ctx := context.Background()
	repo := NewMockRepository()

	p := deviceauth.New(repo, deviceauth.WithExpiresIn(20*time.Millisecond))
	_ = p.Init(plugin.NewContext(nil, nil))

	res, err := p.RequestDeviceCode(ctx, deviceauth.RequestDeviceCodeParams{ClientID: "cli_app"})
	if err != nil {
		t.Fatalf("RequestDeviceCode failed: %v", err)
	}

	time.Sleep(30 * time.Millisecond)

	_, err = p.ExchangeDeviceToken(ctx, deviceauth.ExchangeDeviceTokenParams{
		GrantType:  deviceauth.OAuth2DeviceGrantType,
		DeviceCode: res.DeviceCode,
	})
	if !errors.Is(err, deviceauth.ErrCodeExpired) {
		t.Fatalf("expected ErrCodeExpired, got: %v", err)
	}
}

func TestDeviceAuth_Concurrency(t *testing.T) {
	ctx := context.Background()
	repo := NewMockRepository()

	testUser := &entity.User{ID: "usr_concurrent", Name: "Concurrent User"}
	repo.users[testUser.ID] = testUser

	p := deviceauth.New(repo, deviceauth.WithInterval(1*time.Millisecond))
	_ = p.Init(plugin.NewContext(nil, nil))

	res, err := p.RequestDeviceCode(ctx, deviceauth.RequestDeviceCodeParams{ClientID: "cli_app"})
	if err != nil {
		t.Fatalf("RequestDeviceCode failed: %v", err)
	}

	if err := p.ApproveDeviceCode(ctx, deviceauth.ApproveDeviceCodeParams{
		UserID:   testUser.ID,
		UserCode: res.UserCode,
	}); err != nil {
		t.Fatalf("ApproveDeviceCode failed: %v", err)
	}

	time.Sleep(5 * time.Millisecond)

	const goroutines = 20
	var wg sync.WaitGroup
	successCount := 0
	alreadyConsumedCount := 0
	var mu sync.Mutex

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := p.ExchangeDeviceToken(ctx, deviceauth.ExchangeDeviceTokenParams{
				GrantType:  deviceauth.OAuth2DeviceGrantType,
				DeviceCode: res.DeviceCode,
			})
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				successCount++
			} else if errors.Is(err, deviceauth.ErrAlreadyConsumed) || errors.Is(err, deviceauth.ErrInvalidDeviceCode) {
				alreadyConsumedCount++
			}
		}()
	}

	wg.Wait()

	if successCount != 1 {
		t.Errorf("expected exactly 1 successful token exchange, got %d", successCount)
	}
	if alreadyConsumedCount != goroutines-1 {
		t.Errorf("expected %d goroutines to receive ErrAlreadyConsumed, got %d", goroutines-1, alreadyConsumedCount)
	}
}
