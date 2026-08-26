package apikey_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/BladiCreator/go-modular-auth/domain/entity"
	"github.com/BladiCreator/go-modular-auth/plugins/apikey"
)

type mockRepository struct {
	mu      sync.Mutex
	keys    map[string]*apikey.ApiKey
	byHash  map[string]*apikey.ApiKey
	users   map[string]*entity.User
	updated bool
}

func newMockRepository() *mockRepository {
	return &mockRepository{
		keys:   make(map[string]*apikey.ApiKey),
		byHash: make(map[string]*apikey.ApiKey),
		users:  make(map[string]*entity.User),
	}
}

func (m *mockRepository) CreateApiKey(ctx context.Context, apiKey *apikey.ApiKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.keys[apiKey.ID] = apiKey
	m.byHash[apiKey.Key] = apiKey
	return nil
}

func (m *mockRepository) FindApiKeyByID(ctx context.Context, id string) (*apikey.ApiKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key, ok := m.keys[id]
	if !ok {
		return nil, apikey.ErrKeyNotFound
	}
	return key, nil
}

func (m *mockRepository) FindApiKeyByKeyHash(ctx context.Context, keyHash string) (*apikey.ApiKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key, ok := m.byHash[keyHash]
	if !ok {
		return nil, apikey.ErrKeyNotFound
	}
	return key, nil
}

func (m *mockRepository) UpdateApiKey(ctx context.Context, apiKey *apikey.ApiKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.keys[apiKey.ID] = apiKey
	m.byHash[apiKey.Key] = apiKey
	m.updated = true
	return nil
}

func (m *mockRepository) DeleteApiKey(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key, ok := m.keys[id]
	if !ok {
		return apikey.ErrKeyNotFound
	}
	delete(m.keys, id)
	delete(m.byHash, key.Key)
	return nil
}

func (m *mockRepository) ListApiKeysByReferenceID(ctx context.Context, configID string, referenceID string, limit int, offset int) ([]*apikey.ApiKey, int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var result []*apikey.ApiKey
	for _, key := range m.keys {
		if key.ConfigID == configID && key.ReferenceID == referenceID {
			result = append(result, key)
		}
	}
	return result, int64(len(result)), nil
}

func (m *mockRepository) DeleteExpiredApiKeys(ctx context.Context) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	var count int64
	for id, key := range m.keys {
		if key.ExpiresAt != nil && now.After(*key.ExpiresAt) {
			delete(m.keys, id)
			delete(m.byHash, key.Key)
			count++
		}
	}
	return count, nil
}

func (m *mockRepository) GetUserByID(ctx context.Context, userID string) (*entity.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[userID]
	if !ok {
		return nil, nil
	}
	return u, nil
}

func TestCreateAndVerifyApiKey(t *testing.T) {
	repo := newMockRepository()
	user := &entity.User{ID: "usr_123", Name: "Alice", Email: "alice@example.com"}
	repo.users[user.ID] = user

	plugin := apikey.New(repo, apikey.WithDefaultPrefix("sk_test_"))
	ctx := context.Background()

	res, err := plugin.CreateKey(ctx, apikey.CreateApiKeyParams{
		Name:        stringPtr("Test Key"),
		ReferenceID: "usr_123",
		Permissions: map[string][]string{
			"documents": {"read", "write"},
		},
		Metadata: map[string]any{
			"environment": "staging",
		},
	})
	if err != nil {
		t.Fatalf("CreateKey failed: %v", err)
	}

	if res.RawKey == "" {
		t.Fatal("RawKey should not be empty")
	}
	if res.ApiKey.Prefix != "sk_test_" {
		t.Errorf("Expected prefix sk_test_, got %s", res.ApiKey.Prefix)
	}

	// Verify key
	verifyRes, err := plugin.VerifyKey(ctx, apikey.VerifyApiKeyParams{
		Key: res.RawKey,
		RequiredPermissions: map[string][]string{
			"documents": {"read"},
		},
	})
	if err != nil {
		t.Fatalf("VerifyKey failed: %v", err)
	}

	if !verifyRes.Valid {
		t.Fatalf("Expected valid key, got error: %s", verifyRes.Error)
	}
	if verifyRes.User == nil || verifyRes.User.ID != "usr_123" {
		t.Fatalf("Expected user usr_123, got %v", verifyRes.User)
	}
}

func TestDisabledAndExpiredApiKey(t *testing.T) {
	repo := newMockRepository()
	plugin := apikey.New(repo)
	ctx := context.Background()

	res, err := plugin.CreateKey(ctx, apikey.CreateApiKeyParams{
		ReferenceID: "usr_456",
	})
	if err != nil {
		t.Fatalf("CreateKey failed: %v", err)
	}

	// Disable key
	_, err = plugin.UpdateKey(ctx, apikey.UpdateApiKeyParams{
		ID:      res.ApiKey.ID,
		Enabled: boolPtr(false),
	})
	if err != nil {
		t.Fatalf("UpdateKey failed: %v", err)
	}

	verifyRes, err := plugin.VerifyKey(ctx, apikey.VerifyApiKeyParams{Key: res.RawKey})
	if err != nil {
		t.Fatalf("VerifyKey returned unexpected error: %v", err)
	}
	if verifyRes.Valid {
		t.Fatal("Disabled key should not be valid")
	}
	if verifyRes.Error != apikey.ErrKeyDisabled.Error() {
		t.Errorf("Expected ErrKeyDisabled, got %s", verifyRes.Error)
	}

	// Expiration test
	expiredTime := time.Now().Add(-1 * time.Hour)
	expRes, err := plugin.CreateKey(ctx, apikey.CreateApiKeyParams{
		ReferenceID: "usr_456",
		ExpiresAt:   &expiredTime,
	})
	if err != nil {
		t.Fatalf("CreateKey failed: %v", err)
	}

	verifyExp, err := plugin.VerifyKey(ctx, apikey.VerifyApiKeyParams{Key: expRes.RawKey})
	if err != nil {
		t.Fatalf("VerifyKey returned error: %v", err)
	}
	if verifyExp.Valid {
		t.Fatal("Expired key should not be valid")
	}
	if verifyExp.Error != apikey.ErrKeyExpired.Error() {
		t.Errorf("Expected ErrKeyExpired, got %s", verifyExp.Error)
	}
}

func TestQuotaAndRateLimit(t *testing.T) {
	repo := newMockRepository()
	plugin := apikey.New(repo)
	ctx := context.Background()

	// Remaining quota test
	res, err := plugin.CreateKey(ctx, apikey.CreateApiKeyParams{
		ReferenceID: "usr_789",
		Remaining:   int64Ptr(1),
	})
	if err != nil {
		t.Fatalf("CreateKey failed: %v", err)
	}

	// First request succeeds and decrements remaining to 0
	verify1, err := plugin.VerifyKey(ctx, apikey.VerifyApiKeyParams{Key: res.RawKey})
	if err != nil || !verify1.Valid {
		t.Fatalf("First request should succeed: %v", verify1.Error)
	}

	// Second request fails due to quota limit
	verify2, err := plugin.VerifyKey(ctx, apikey.VerifyApiKeyParams{Key: res.RawKey})
	if err != nil {
		t.Fatalf("VerifyKey returned error: %v", err)
	}
	if verify2.Valid {
		t.Fatal("Second request should fail due to quota limit")
	}
	if verify2.Error != apikey.ErrUsageExceeded.Error() {
		t.Errorf("Expected ErrUsageExceeded, got %s", verify2.Error)
	}
}

func TestDeferUpdates(t *testing.T) {
	repo := newMockRepository()
	plugin := apikey.New(repo, apikey.WithDeferUpdates(true))
	ctx := context.Background()

	res, err := plugin.CreateKey(ctx, apikey.CreateApiKeyParams{
		ReferenceID: "usr_async",
	})
	if err != nil {
		t.Fatalf("CreateKey failed: %v", err)
	}

	verifyRes, err := plugin.VerifyKey(ctx, apikey.VerifyApiKeyParams{Key: res.RawKey})
	if err != nil || !verifyRes.Valid {
		t.Fatalf("VerifyKey failed: %v", err)
	}

	// Allow background goroutine to execute
	time.Sleep(50 * time.Millisecond)

	repo.mu.Lock()
	updated := repo.updated
	repo.mu.Unlock()

	if !updated {
		t.Fatal("Expected background goroutine to update key in repository")
	}
}

func TestHTTPMiddleware(t *testing.T) {
	repo := newMockRepository()
	user := &entity.User{ID: "usr_mw", Name: "Bob"}
	repo.users[user.ID] = user

	plugin := apikey.New(repo)
	ctx := context.Background()

	res, err := plugin.CreateKey(ctx, apikey.CreateApiKeyParams{
		ReferenceID: "usr_mw",
	})
	if err != nil {
		t.Fatalf("CreateKey failed: %v", err)
	}

	handler := plugin.Authenticate()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqUser, ok := r.Context().Value(apikey.UserContextKey).(*entity.User)
		if !ok || reqUser == nil {
			t.Fatal("User not found in request context")
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}))

	req := httptest.NewRequest("GET", "/api/protected", nil)
	req.Header.Set("X-API-Key", res.RawKey)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Expected HTTP 200, got %d", rec.Code)
	}
}

func stringPtr(s string) *string { return &s }
func boolPtr(b bool) *bool       { return &b }
func int64Ptr(i int64) *int64    { return &i }
