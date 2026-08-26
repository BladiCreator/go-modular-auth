package deviceauth_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/BladiCreator/go-modular-auth/plugins/deviceauth"
)

func TestDeviceAuthHTTPHandlers(t *testing.T) {
	repo := NewMockRepository()
	p := deviceauth.New(repo)

	t.Run("HandleDeviceCode urlencoded request", func(t *testing.T) {
		form := url.Values{}
		form.Set("client_id", "cli_123")
		form.Set("scope", "openid profile")

		req := httptest.NewRequest(http.MethodPost, "/device/code", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()

		p.ServeDeviceCode(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected status 200, got %d", rec.Code)
		}

		var resp deviceauth.DeviceCodeResponse
		if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}
		if resp.UserCode == "" || resp.DeviceCode == "" {
			t.Fatalf("expected non-empty user code and device code")
		}
	})

	t.Run("HandleDeviceCode method not allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/device/code", nil)
		rec := httptest.NewRecorder()

		p.ServeDeviceCode(rec, req)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("expected status 405, got %d", rec.Code)
		}
	})
}
