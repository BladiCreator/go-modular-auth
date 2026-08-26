package captcha

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/BladiCreator/go-modular-auth/plugin"
)

func TestDefaultIPExtractor(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/test", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.195, 70.41.3.18")
	if ip := DefaultIPExtractor(req); ip != "203.0.113.195" {
		t.Errorf("expected 203.0.113.195, got %s", ip)
	}

	req2 := httptest.NewRequest(http.MethodPost, "/test", nil)
	req2.Header.Set("X-Real-IP", "198.51.100.1")
	if ip := DefaultIPExtractor(req2); ip != "198.51.100.1" {
		t.Errorf("expected 198.51.100.1, got %s", ip)
	}

	req3 := httptest.NewRequest(http.MethodPost, "/test", nil)
	req3.RemoteAddr = "192.0.2.1:12345"
	if ip := DefaultIPExtractor(req3); ip != "192.0.2.1" {
		t.Errorf("expected 192.0.2.1, got %s", ip)
	}
}

func TestCaptchaPlugin_Initialization(t *testing.T) {
	p := New(WithSecretKey("secret-123"))
	if p.ID() != PluginID {
		t.Errorf("expected plugin ID %s, got %s", PluginID, p.ID())
	}

	ctx := plugin.NewContext(nil, nil)
	if err := p.Init(ctx); err != nil {
		t.Fatalf("Init returned unexpected error: %v", err)
	}
}

func TestCaptchaPlugin_UnprotectedAndExemptPath(t *testing.T) {
	p := New(
		WithSecretKey("secret-key"),
		WithEndpoints([]string{"/sign-up/email"}),
		WithExemptEndpoints([]string{"/sign-in/email-otp"}),
	)

	handler := p.Protect()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}))

	// Unprotected path
	req := httptest.NewRequest(http.MethodPost, "/public-endpoint", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200 for unprotected path, got %d", rec.Code)
	}

	// Exempt path
	req2 := httptest.NewRequest(http.MethodPost, "/sign-in/email-otp", nil)
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Errorf("expected status 200 for exempt path, got %d", rec2.Code)
	}
}

func TestCaptchaPlugin_MissingSecretKey(t *testing.T) {
	p := New(WithEndpoints([]string{"/sign-up/email"}))

	handler := p.Protect()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/sign-up/email", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 InternalServerError when SecretKey is missing, got %d", rec.Code)
	}
}

func TestCaptchaPlugin_MissingHeader(t *testing.T) {
	p := New(
		WithSecretKey("secret-123"),
		WithEndpoints([]string{"/sign-up/email"}),
	)

	handler := p.Protect()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/sign-up/email", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 BadRequest when x-captcha-response is missing, got %d", rec.Code)
	}
}

func TestCaptchaPlugin_Turnstile_SuccessAndFailures(t *testing.T) {
	var mockResp turnstileResponse

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/json" {
			http.Error(w, "invalid content type", http.StatusBadRequest)
			return
		}

		body, _ := io.ReadAll(r.Body)
		var reqData map[string]string
		_ = json.Unmarshal(body, &reqData)

		if reqData["secret"] != "valid-secret" || reqData["response"] != "valid-token" {
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(turnstileResponse{Success: false})
			return
		}

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(mockResp)
	}))
	defer ts.Close()

	// 1. Success case
	mockResp = turnstileResponse{
		Success:  true,
		Action:   "login",
		Hostname: "example.com",
	}

	p := New(
		WithProvider(ProviderCloudflareTurnstile),
		WithSecretKey("valid-secret"),
		WithSiteVerifyURLOverride(ts.URL),
		WithExpectedAction("login"),
		WithAllowedHostnames([]string{"example.com"}),
	)

	handler := p.Protect()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Authorized"))
	}))

	req := httptest.NewRequest(http.MethodPost, "/sign-in/email", nil)
	req.Header.Set(HeaderCaptchaResponse, "valid-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d (body: %s)", rec.Code, rec.Body.String())
	}

	// 2. Action mismatch
	pAction := New(
		WithProvider(ProviderCloudflareTurnstile),
		WithSecretKey("valid-secret"),
		WithSiteVerifyURLOverride(ts.URL),
		WithExpectedAction("signup"),
	)
	handlerAction := pAction.Protect()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	reqAction := httptest.NewRequest(http.MethodPost, "/sign-in/email", nil)
	reqAction.Header.Set(HeaderCaptchaResponse, "valid-token")
	recAction := httptest.NewRecorder()
	handlerAction.ServeHTTP(recAction, reqAction)

	if recAction.Code != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden for action mismatch, got %d", recAction.Code)
	}

	// 3. Hostname mismatch
	pHost := New(
		WithProvider(ProviderCloudflareTurnstile),
		WithSecretKey("valid-secret"),
		WithSiteVerifyURLOverride(ts.URL),
		WithAllowedHostnames([]string{"otherdomain.com"}),
	)
	handlerHost := pHost.Protect()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	reqHost := httptest.NewRequest(http.MethodPost, "/sign-in/email", nil)
	reqHost.Header.Set(HeaderCaptchaResponse, "valid-token")
	recHost := httptest.NewRecorder()
	handlerHost.ServeHTTP(recHost, reqHost)

	if recHost.Code != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden for hostname mismatch, got %d", recHost.Code)
	}
}

func TestCaptchaPlugin_GoogleRecaptcha_Score(t *testing.T) {
	var scoreResp recaptchaResponse

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(scoreResp)
	}))
	defer ts.Close()

	// High score
	scoreResp = recaptchaResponse{Success: true, Score: 0.8, Action: "submit", Hostname: "test.com"}
	p := New(
		WithProvider(ProviderGoogleRecaptcha),
		WithSecretKey("secret"),
		WithSiteVerifyURLOverride(ts.URL),
		WithMinScore(0.5),
	)

	handler := p.Protect()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/sign-up/email", nil)
	req.Header.Set(HeaderCaptchaResponse, "token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 OK for high score, got %d", rec.Code)
	}

	// Low score
	scoreResp = recaptchaResponse{Success: true, Score: 0.3, Action: "submit", Hostname: "test.com"}
	recLow := httptest.NewRecorder()
	handler.ServeHTTP(recLow, req)

	if recLow.Code != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden for low score, got %d", recLow.Code)
	}
}

func TestCaptchaPlugin_HCaptcha_And_CaptchaFox(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("sitekey") != "site-123" {
			_ = json.NewEncoder(w).Encode(map[string]bool{"success": false})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
	}))
	defer ts.Close()

	// hCaptcha
	pH := New(
		WithProvider(ProviderHCaptcha),
		WithSecretKey("secret"),
		WithSiteKey("site-123"),
		WithSiteVerifyURLOverride(ts.URL),
	)
	handlerH := pH.Protect()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	reqH := httptest.NewRequest(http.MethodPost, "/sign-up/email", nil)
	reqH.Header.Set(HeaderCaptchaResponse, "token")
	recH := httptest.NewRecorder()
	handlerH.ServeHTTP(recH, reqH)

	if recH.Code != http.StatusOK {
		t.Errorf("expected 200 for valid hCaptcha, got %d", recH.Code)
	}

	// CaptchaFox
	pFox := New(
		WithProvider(ProviderCaptchaFox),
		WithSecretKey("secret"),
		WithSiteKey("site-123"),
		WithSiteVerifyURLOverride(ts.URL),
	)
	handlerFox := pFox.Protect()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	recFox := httptest.NewRecorder()
	handlerFox.ServeHTTP(recFox, reqH)

	if recFox.Code != http.StatusOK {
		t.Errorf("expected 200 for valid CaptchaFox, got %d", recFox.Code)
	}
}

func TestCaptchaPlugin_Timeout(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(turnstileResponse{Success: true})
	}))
	defer ts.Close()

	p := New(
		WithProvider(ProviderCloudflareTurnstile),
		WithSecretKey("secret"),
		WithSiteVerifyURLOverride(ts.URL),
		WithTimeout(30*time.Millisecond),
	)

	handler := p.Protect()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	req := httptest.NewRequest(http.MethodPost, "/sign-up/email", nil)
	req.Header.Set(HeaderCaptchaResponse, "token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 InternalServerError on timeout, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), ErrServiceUnavailable.Error()) {
		t.Errorf("expected body to contain ErrServiceUnavailable, got %s", rec.Body.String())
	}
}
