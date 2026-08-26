package admin_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/BladiCreator/go-modular-auth/adapters/memory"
	"github.com/BladiCreator/go-modular-auth/domain/entity"
	"github.com/BladiCreator/go-modular-auth/plugins/admin"
)

func TestAdminHTTPMiddleware(t *testing.T) {
	repo := memory.New()
	p := admin.New(repo, admin.WithAdminRoles("admin", "superadmin"))

	permHandler := p.RequirePermission(admin.Permissions{
		admin.ResourceUser: {admin.ActionBan},
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	roleHandler := p.RequireAdmin()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	t.Run("user role denied for ban action", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/admin/ban", nil)
		ctx := context.WithValue(req.Context(), admin.CallerContextKey, &entity.User{
			ID:   "usr_1",
			Role: "user",
		})
		rec := httptest.NewRecorder()
		permHandler.ServeHTTP(rec, req.WithContext(ctx))
		if rec.Code != http.StatusForbidden {
			t.Fatalf("expected status 403, got %d", rec.Code)
		}
	})

	t.Run("admin role allowed for ban action", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/admin/ban", nil)
		ctx := context.WithValue(req.Context(), admin.CallerContextKey, &entity.User{
			ID:   "usr_admin",
			Role: "admin",
		})
		rec := httptest.NewRecorder()
		permHandler.ServeHTTP(rec, req.WithContext(ctx))
		if rec.Code != http.StatusOK {
			t.Fatalf("expected status 200, got %d", rec.Code)
		}
	})

	t.Run("RequireAdmin denies non-admin", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/admin/dashboard", nil)
		ctx := context.WithValue(req.Context(), admin.CallerContextKey, &entity.User{
			ID:   "usr_1",
			Role: "user",
		})
		rec := httptest.NewRecorder()
		roleHandler.ServeHTTP(rec, req.WithContext(ctx))
		if rec.Code != http.StatusForbidden {
			t.Fatalf("expected status 403, got %d", rec.Code)
		}
	})

	t.Run("RequireAdmin allows superadmin", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/admin/dashboard", nil)
		ctx := context.WithValue(req.Context(), admin.CallerContextKey, &entity.User{
			ID:   "usr_super",
			Role: "superadmin",
		})
		rec := httptest.NewRecorder()
		roleHandler.ServeHTTP(rec, req.WithContext(ctx))
		if rec.Code != http.StatusOK {
			t.Fatalf("expected status 200, got %d", rec.Code)
		}
	})
}
