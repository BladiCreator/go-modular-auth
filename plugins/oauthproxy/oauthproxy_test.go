package oauthproxy_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/BladiCreator/go-modular-auth/domain/entity"
	"github.com/BladiCreator/go-modular-auth/plugins/oauthproxy"
)

const testSecret = "super-secret-shared-key-1234567890"

func TestCrypto_EncryptDecrypt(t *testing.T) {
	plaintext := []byte("Hello OAuth Proxy!")

	ciphertext, err := oauthproxy.Encrypt(testSecret, plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	if ciphertext == "" {
		t.Fatal("Expected non-empty ciphertext")
	}

	decrypted, err := oauthproxy.Decrypt(testSecret, ciphertext)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("Expected decrypted %q, got %q", string(plaintext), string(decrypted))
	}

	// Test wrong key
	_, err = oauthproxy.Decrypt("wrong-secret-key", ciphertext)
	if err == nil {
		t.Error("Expected decryption error with wrong secret key")
	}

	// Test invalid ciphertext
	_, err = oauthproxy.Decrypt(testSecret, "invalid-base64-content!")
	if err == nil {
		t.Error("Expected error for invalid ciphertext base64")
	}
}

func TestUtils_ResolveCurrentURL_And_SkipProxy(t *testing.T) {
	cfg := oauthproxy.DefaultConfig()
	cfg.ProductionURL = "https://myapp.com"
	cfg.Secret = testSecret

	// Test 1: Explicit CurrentURL
	cfg.CurrentURL = "https://preview-123.myapp.com"
	u, err := oauthproxy.ResolveCurrentURL(nil, cfg)
	if err != nil || u.String() != "https://preview-123.myapp.com" {
		t.Errorf("Expected explicit CurrentURL, got %v (err: %v)", u, err)
	}

	// Test 2: Vendor Environment Variable
	cfg.CurrentURL = ""
	_ = os.Setenv("VERCEL_URL", "preview-vercel.myapp.com")
	defer func() { _ = os.Unsetenv("VERCEL_URL") }()

	u, err = oauthproxy.ResolveCurrentURL(nil, cfg)
	if err != nil || u.String() != "https://preview-vercel.myapp.com" {
		t.Errorf("Expected VERCEL_URL environment variable resolution, got %v (err: %v)", u, err)
	}

	// Test 3: CheckSkipProxy header
	_ = os.Unsetenv("VERCEL_URL")
	req := httptest.NewRequest("GET", "https://preview-123.myapp.com/login", nil)
	req.Header.Set("X-Skip-OAuth-Proxy", "true")

	if !oauthproxy.CheckSkipProxy(req, cfg) {
		t.Error("Expected CheckSkipProxy to return true when skip header is set")
	}

	// Test 4: CheckSkipProxy on Production URL request
	reqProd := httptest.NewRequest("GET", "https://myapp.com/login", nil)
	if !oauthproxy.CheckSkipProxy(reqProd, cfg) {
		t.Error("Expected CheckSkipProxy to return true when host matches ProductionURL")
	}
}

func TestOAuthProxy_StatePackage(t *testing.T) {
	p := oauthproxy.New(
		oauthproxy.WithSecret(testSecret),
		oauthproxy.WithProductionURL("https://myapp.com"),
	)

	stateStr, err := p.CreateStatePackage("orig_state_123", "/dashboard", "https://preview-999.myapp.com")
	if err != nil {
		t.Fatalf("CreateStatePackage failed: %v", err)
	}

	pkg, err := p.ParseStatePackage(stateStr)
	if err != nil {
		t.Fatalf("ParseStatePackage failed: %v", err)
	}

	if pkg.State != "orig_state_123" {
		t.Errorf("Expected State 'orig_state_123', got %q", pkg.State)
	}
	if pkg.CallbackURL != "/dashboard" {
		t.Errorf("Expected CallbackURL '/dashboard', got %q", pkg.CallbackURL)
	}
	if pkg.CurrentURL != "https://preview-999.myapp.com" {
		t.Errorf("Expected CurrentURL 'https://preview-999.myapp.com', got %q", pkg.CurrentURL)
	}
}

func TestOAuthProxy_PassthroughPayload(t *testing.T) {
	p := oauthproxy.New(
		oauthproxy.WithSecret(testSecret),
		oauthproxy.WithMaxAge(2 * time.Second),
	)

	payload := &oauthproxy.PassthroughPayload{
		User: entity.User{
			ID:    "usr_123",
			Email: "test@example.com",
			Name:  "Test User",
		},
		Account: entity.Account{
			ID:       "acc_123",
			UserID:   "usr_123",
			Provider: "github",
		},
		CallbackURL: "/welcome",
		Timestamp:   time.Now().UnixMilli(),
	}

	encryptedProfile, err := p.CreatePassthroughPayload(payload)
	if err != nil {
		t.Fatalf("CreatePassthroughPayload failed: %v", err)
	}

	decodedPayload, err := p.ParsePassthroughPayload(encryptedProfile)
	if err != nil {
		t.Fatalf("ParsePassthroughPayload failed: %v", err)
	}

	if decodedPayload.User.ID != "usr_123" || decodedPayload.User.Email != "test@example.com" {
		t.Errorf("User struct mismatch after payload decoding: %+v", decodedPayload.User)
	}
	if decodedPayload.Account.Provider != "github" {
		t.Errorf("Account struct mismatch after payload decoding: %+v", decodedPayload.Account)
	}

	// Test Expired Payload
	expiredPayload := &oauthproxy.PassthroughPayload{
		User:      entity.User{ID: "usr_expired"},
		Timestamp: time.Now().Add(-10 * time.Second).UnixMilli(),
	}
	encryptedExpired, err := p.CreatePassthroughPayload(expiredPayload)
	if err != nil {
		t.Fatalf("CreatePassthroughPayload failed for expired: %v", err)
	}

	_, err = p.ParsePassthroughPayload(encryptedExpired)
	if err == nil {
		t.Error("Expected error when parsing payload exceeding MaxAge")
	}
}

func TestOAuthProxy_FullFlow(t *testing.T) {
	var capturedUser *entity.User

	p := oauthproxy.New(
		oauthproxy.WithSecret(testSecret),
		oauthproxy.WithProductionURL("https://myapp.com"),
		oauthproxy.WithCurrentURL("https://preview-flow.myapp.com"),
		oauthproxy.WithOnSuccess(func(w http.ResponseWriter, r *http.Request, payload *oauthproxy.PassthroughPayload) error {
			capturedUser = &payload.User
			return nil
		}),
	)

	// Step 1: Create StatePackage on Preview
	stateStr, err := p.CreateStatePackage("my_oauth_state", "/home", "https://preview-flow.myapp.com")
	if err != nil {
		t.Fatalf("CreateStatePackage failed: %v", err)
	}

	// Step 2: Create PassthroughPayload on Production
	payload := &oauthproxy.PassthroughPayload{
		User: entity.User{
			ID:    "usr_preview_999",
			Email: "preview@golang.org",
			Name:  "Gopher Preview",
		},
		Account: entity.Account{
			ID:       "acc_preview_999",
			UserID:   "usr_preview_999",
			Provider: "google",
		},
		State:       stateStr,
		CallbackURL: "/home",
		Timestamp:   time.Now().UnixMilli(),
	}

	encryptedProfile, err := p.CreatePassthroughPayload(payload)
	if err != nil {
		t.Fatalf("CreatePassthroughPayload failed: %v", err)
	}

	// Step 3: Preview Server receives ServeOAuthProxyCallback request
	req := httptest.NewRequest("GET", "/api/auth/oauth-proxy-callback?profile="+url.QueryEscape(encryptedProfile), nil)
	rec := httptest.NewRecorder()

	p.ServeOAuthProxyCallback(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("Expected HTTP status 302 Found, got %d. Body: %s", rec.Code, rec.Body.String())
	}

	if rec.Header().Get("Location") != "/home" {
		t.Errorf("Expected redirect Location '/home', got %q", rec.Header().Get("Location"))
	}

	if capturedUser == nil || capturedUser.Email != "preview@golang.org" {
		t.Errorf("Expected OnSuccess hook to capture user preview@golang.org, got %+v", capturedUser)
	}
}
