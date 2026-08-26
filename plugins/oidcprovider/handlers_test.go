package oidcprovider_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/BladiCreator/go-modular-auth/plugins/oidcprovider"
)

func TestOIDCHTTPHandlers(t *testing.T) {
	repo := NewMockRepository()
	p := oidcprovider.New(repo,
		oidcprovider.WithIssuer("http://localhost:8080"),
		oidcprovider.WithBaseURL("http://localhost:8080"),
	)

	t.Run("HandleDiscoveryMetadata returns 200 JSON", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
		rec := httptest.NewRecorder()
		p.ServeDiscoveryMetadata(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected status 200, got %d", rec.Code)
		}
		if rec.Header().Get("Content-Type") != "application/json" {
			t.Fatalf("expected application/json content type")
		}
	})

	t.Run("HandleJWKS returns 200 JSON", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
		rec := httptest.NewRecorder()
		p.ServeJWKS(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected status 200, got %d", rec.Code)
		}
		if rec.Header().Get("Content-Type") != "application/json" {
			t.Fatalf("expected application/json content type")
		}
	})
}
