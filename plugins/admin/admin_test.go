package admin_test

import (
	"context"
	"errors"
	"testing"
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	"github.com/BladiCreator/go-modular-auth/adapter"
	adaptermem "github.com/BladiCreator/go-modular-auth/adapter/memory"
	admin "github.com/BladiCreator/go-modular-auth-admin"
	"github.com/BladiCreator/go-modular-auth-admin/plugins"
	corecache "github.com/BladiCreator/go-modular-auth/cache/memory"
)

func setupTestAuth(t *testing.T) (*auth.Auth, plugins.Admin, adapter.Adapter) {
	t.Helper()
	ad := adaptermem.New()
	cCache := corecache.New()

	adminModule := admin.New()

	a, err := auth.New(auth.Config{
		Adapter: ad,
		Cache:   cCache,
		Plugins: []auth.PluginModule{adminModule},
	})
	if err != nil {
		t.Fatalf("auth.New failed: %v", err)
	}

	adm, err := auth.Get[plugins.Admin](a)
	if err != nil {
		t.Fatalf("auth.Get[plugins.Admin] failed: %v", err)
	}

	return a, adm, ad
}

func bootstrapAdmin(ctx context.Context, ad adapter.Adapter, userID, email string) error {
	affected, err := ad.Update(ctx, admin.ModelAdminUsers, []adapter.Condition{adapter.Eq("user_id", userID)}, map[string]any{
		"is_admin":   true,
		"role":       "superadmin",
		"updated_at": time.Now(),
	})
	if err != nil {
		return err
	}
	if affected == 0 {
		_, err = ad.Create(ctx, admin.ModelAdminUsers, map[string]any{
			"user_id":    userID,
			"email":      email,
			"disabled":   false,
			"is_admin":   true,
			"role":       "superadmin",
			"created_at": time.Now(),
			"updated_at": time.Now(),
		})
		return err
	}
	return nil
}

func TestAdmin_EndToEnd(t *testing.T) {
	ctx := context.Background()
	a, adm, ad := setupTestAuth(t)

	// 1. Create Administrator User and Regular User
	adminRes, err := a.SignUp(ctx, auth.SignUpInput{
		Email:    "superadmin@example.com",
		Password: "Password123!",
	})
	if err != nil {
		t.Fatalf("SignUp admin failed: %v", err)
	}
	adminPrincipal := adminRes.Principal()

	// Bootstrap admin role in adapter
	if err := bootstrapAdmin(ctx, ad, adminPrincipal.Subject, "superadmin@example.com"); err != nil {
		t.Fatalf("bootstrapAdmin failed: %v", err)
	}

	userRes, err := a.SignUp(ctx, auth.SignUpInput{
		Email:    "member@example.com",
		Password: "Password123!",
	})
	if err != nil {
		t.Fatalf("SignUp regular user failed: %v", err)
	}
	targetUserID := userRes.User.ID

	// 2. LookupUser
	detail, err := adm.LookupUser(ctx, adminPrincipal, targetUserID)
	if err != nil {
		t.Fatalf("LookupUser failed: %v", err)
	}
	if detail.User.Email != "member@example.com" {
		t.Fatalf("unexpected user email: %s", detail.User.Email)
	}
	if len(detail.Credentials) == 0 {
		t.Fatalf("expected credentials in detail, got 0")
	}

	// 3. LookupUserByEmail
	detailEmail, err := adm.LookupUserByEmail(ctx, adminPrincipal, "member@example.com")
	if err != nil {
		t.Fatalf("LookupUserByEmail failed: %v", err)
	}
	if detailEmail.User.ID != targetUserID {
		t.Fatalf("expected ID %s, got %s", targetUserID, detailEmail.User.ID)
	}

	// 4. ListUsers
	listRes, err := adm.ListUsers(ctx, adminPrincipal, admin.ListFilter{Limit: 10})
	if err != nil {
		t.Fatalf("ListUsers failed: %v", err)
	}
	if listRes.Total < 2 {
		t.Fatalf("expected at least 2 users, got %d", listRes.Total)
	}

	// 5. InspectAccounts and InspectCredentials
	accts, err := adm.InspectAccounts(ctx, adminPrincipal, targetUserID)
	if err != nil {
		t.Fatalf("InspectAccounts failed: %v", err)
	}
	if len(accts) == 0 {
		t.Fatalf("expected accounts for user, got 0")
	}

	creds, err := adm.InspectCredentials(ctx, adminPrincipal, targetUserID)
	if err != nil {
		t.Fatalf("InspectCredentials failed: %v", err)
	}
	if len(creds) == 0 {
		t.Fatalf("expected credentials, got 0")
	}

	// 6. VerifyUserEmail
	if err := adm.VerifyUserEmail(ctx, adminPrincipal, targetUserID); err != nil {
		t.Fatalf("VerifyUserEmail failed: %v", err)
	}
	detail, _ = adm.LookupUser(ctx, adminPrincipal, targetUserID)
	if !detail.User.EmailVerified {
		t.Fatalf("expected EmailVerified true after VerifyUserEmail")
	}

	// 7. InitiatePasswordReset
	token, err := adm.InitiatePasswordReset(ctx, adminPrincipal, targetUserID)
	if err != nil {
		t.Fatalf("InitiatePasswordReset failed: %v", err)
	}
	if token == "" {
		t.Fatalf("expected non-empty reset token")
	}

	// 8. Disable User & Verify SignIn Blocked
	if err := adm.DisableUser(ctx, adminPrincipal, targetUserID, "Policy violation"); err != nil {
		t.Fatalf("DisableUser failed: %v", err)
	}

	// Attempt sign-in with disabled user -> must fail with ErrUserDisabled
	_, err = a.SignIn(ctx, auth.SignInInput{
		Email:    "member@example.com",
		Password: "Password123!",
	})
	if !errors.Is(err, admin.ErrUserDisabled) {
		t.Fatalf("expected ErrUserDisabled, got %v", err)
	}

	// 9. Enable User & Verify SignIn Allowed
	if err := adm.EnableUser(ctx, adminPrincipal, targetUserID); err != nil {
		t.Fatalf("EnableUser failed: %v", err)
	}
	_, err = a.SignIn(ctx, auth.SignInInput{
		Email:    "member@example.com",
		Password: "Password123!",
	})
	if err != nil {
		t.Fatalf("SignIn should succeed after EnableUser, got %v", err)
	}

	// 10. RevokeUserSessions
	if err := adm.RevokeUserSessions(ctx, adminPrincipal, targetUserID); err != nil {
		t.Fatalf("RevokeUserSessions failed: %v", err)
	}

	// 11. DeleteUser
	if err := adm.DeleteUser(ctx, adminPrincipal, targetUserID); err != nil {
		t.Fatalf("DeleteUser failed: %v", err)
	}

	// Verify user deleted in Core and Admin
	_, err = adm.LookupUser(ctx, adminPrincipal, targetUserID)
	if !errors.Is(err, admin.ErrUserNotFound) {
		t.Fatalf("expected ErrUserNotFound after deletion, got %v", err)
	}
}
