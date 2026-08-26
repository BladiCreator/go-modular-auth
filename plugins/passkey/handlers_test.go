package passkey_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/BladiCreator/go-modular-auth/adapters/memory"
	"github.com/BladiCreator/go-modular-auth/plugin"
	"github.com/BladiCreator/go-modular-auth/plugins/passkey"
	"github.com/asaskevich/EventBus"
)

func TestPasskeyHTTPHandlers(t *testing.T) {
	repo := memory.New()
	p := passkey.New(repo,
		passkey.WithRPDisplayName("Acme"),
		passkey.WithRPID("localhost"),
		passkey.WithRPOrigins("http://localhost"),
		passkey.WithRequireSessionOnRegistration(false),
	)
	_ = p.Init(plugin.NewContext(nil, EventBus.New()))

	t.Run("HandleRegistrationOptions method not allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/passkey/register/options", nil)
		rec := httptest.NewRecorder()
		p.ServeRegistrationOptions(rec, req)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("expected status 405, got %d", rec.Code)
		}
	})

	t.Run("HandleRegistrationOptions valid payload", func(t *testing.T) {
		payload := passkey.GenerateRegistrationOptionsParams{
			UserID:   "usr_123",
			UserName: "gopher",
		}
		body, _ := json.Marshal(payload)
		req := httptest.NewRequest(http.MethodPost, "/passkey/register/options", bytes.NewReader(body))
		rec := httptest.NewRecorder()
		p.ServeRegistrationOptions(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected status 200, got %d", rec.Code)
		}
	})

	t.Run("HandleAuthenticationOptions valid payload", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/passkey/login/options", nil)
		rec := httptest.NewRecorder()
		p.ServeAuthenticationOptions(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected status 200, got %d", rec.Code)
		}
	})
}
