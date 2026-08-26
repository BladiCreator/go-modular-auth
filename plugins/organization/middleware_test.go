package organization_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/BladiCreator/go-modular-auth/adapters/memory"
	"github.com/BladiCreator/go-modular-auth/plugins/organization"
)

func TestOrganizationHTTPMiddleware(t *testing.T) {
	repo := memory.New()
	p := organization.New(repo)

	// Seed Org and Member
	orgRes, err := p.CreateOrganization(context.Background(), organization.CreateOrganizationParams{
		Name:   "Acme Corp",
		Slug:   "acme",
		UserID: "usr_owner",
	})
	if err != nil {
		t.Fatalf("failed to create org: %v", err)
	}

	handler := p.RequireMember()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		member, ok := r.Context().Value(organization.MemberContextKey).(*organization.Member)
		if !ok || member == nil || member.UserID != "usr_owner" {
			t.Errorf("expected member 'usr_owner'")
		}
		w.WriteHeader(http.StatusOK)
	}))

	t.Run("missing headers returns 401", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/org/members", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected status 401, got %d", rec.Code)
		}
	})

	t.Run("valid org member passes", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/org/members", nil)
		req.Header.Set("X-Organization-ID", orgRes.Organization.ID)
		req.Header.Set("X-User-ID", "usr_owner")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected status 200, got %d", rec.Code)
		}
	})

	t.Run("non-member returns 403", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/org/members", nil)
		req.Header.Set("X-Organization-ID", orgRes.Organization.ID)
		req.Header.Set("X-User-ID", "usr_outsider")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("expected status 403, got %d", rec.Code)
		}
	})
}
