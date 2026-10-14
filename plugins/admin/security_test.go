package admin_test

import (
	"context"
	"errors"
	"testing"

	auth "github.com/BladiCreator/go-modular-auth"
	adaptermem "github.com/BladiCreator/go-modular-auth/adapter/memory"
	admin "github.com/BladiCreator/go-modular-auth-admin"
	"github.com/BladiCreator/go-modular-auth-admin/plugins"
	orgplugin "github.com/BladiCreator/go-modular-auth-organizations"
	corecache "github.com/BladiCreator/go-modular-auth/cache/memory"
)

func TestAdmin_Security_AuthorizationEnforced(t *testing.T) {
	ctx := context.Background()
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
		t.Fatalf("auth.Get failed: %v", err)
	}

	userRes, _ := a.SignUp(ctx, auth.SignUpInput{
		Email:    "unauthorized@example.com",
		Password: "Password123!",
	})
	unauthorizedPrincipal := userRes.Principal()

	// Every administrative call MUST fail with ErrUnauthorized
	if _, err := adm.LookupUser(ctx, unauthorizedPrincipal, "any_id"); !errors.Is(err, admin.ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized on LookupUser, got %v", err)
	}
	if _, err := adm.ListUsers(ctx, unauthorizedPrincipal, admin.ListFilter{}); !errors.Is(err, admin.ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized on ListUsers, got %v", err)
	}
	if err := adm.DisableUser(ctx, unauthorizedPrincipal, "any_id", "reason"); !errors.Is(err, admin.ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized on DisableUser, got %v", err)
	}
	if err := adm.EnableUser(ctx, unauthorizedPrincipal, "any_id"); !errors.Is(err, admin.ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized on EnableUser, got %v", err)
	}
	if err := adm.RevokeUserSessions(ctx, unauthorizedPrincipal, "any_id"); !errors.Is(err, admin.ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized on RevokeUserSessions, got %v", err)
	}
	if _, err := adm.InitiatePasswordReset(ctx, unauthorizedPrincipal, "any_id"); !errors.Is(err, admin.ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized on InitiatePasswordReset, got %v", err)
	}
	if err := adm.VerifyUserEmail(ctx, unauthorizedPrincipal, "any_id"); !errors.Is(err, admin.ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized on VerifyUserEmail, got %v", err)
	}
	if _, err := adm.InspectAccounts(ctx, unauthorizedPrincipal, "any_id"); !errors.Is(err, admin.ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized on InspectAccounts, got %v", err)
	}
	if _, err := adm.InspectCredentials(ctx, unauthorizedPrincipal, "any_id"); !errors.Is(err, admin.ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized on InspectCredentials, got %v", err)
	}
	if err := adm.DeleteUser(ctx, unauthorizedPrincipal, "any_id"); !errors.Is(err, admin.ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized on DeleteUser, got %v", err)
	}
}

func TestAdmin_Security_SelfProtection(t *testing.T) {
	ctx := context.Background()
	a, adm, ad := setupTestAuth(t)

	adminRes, _ := a.SignUp(ctx, auth.SignUpInput{
		Email:    "admin_self@example.com",
		Password: "Password123!",
	})
	adminPrincipal := adminRes.Principal()
	_ = bootstrapAdmin(ctx, ad, adminPrincipal.Subject, "admin_self@example.com")

	// 1. Cannot disable self
	err := adm.DisableUser(ctx, adminPrincipal, adminPrincipal.Subject, "lockout")
	if !errors.Is(err, admin.ErrCannotDisableSelf) {
		t.Fatalf("expected ErrCannotDisableSelf, got %v", err)
	}

	// 2. Cannot delete self
	err = adm.DeleteUser(ctx, adminPrincipal, adminPrincipal.Subject)
	if !errors.Is(err, admin.ErrCannotDeleteSelf) {
		t.Fatalf("expected ErrCannotDeleteSelf, got %v", err)
	}
}

func TestAdmin_Security_NeverExposeSecrets(t *testing.T) {
	ctx := context.Background()
	a, adm, ad := setupTestAuth(t)

	adminRes, _ := a.SignUp(ctx, auth.SignUpInput{
		Email:    "admin_secret_check@example.com",
		Password: "Password123!",
	})
	adminPrincipal := adminRes.Principal()
	_ = bootstrapAdmin(ctx, ad, adminPrincipal.Subject, "admin_secret_check@example.com")

	userRes, _ := a.SignUp(ctx, auth.SignUpInput{
		Email:    "target_secret@example.com",
		Password: "SuperSecretPassword99!",
	})

	creds, err := adm.InspectCredentials(ctx, adminPrincipal, userRes.User.ID)
	if err != nil {
		t.Fatalf("InspectCredentials failed: %v", err)
	}
	if len(creds) == 0 {
		t.Fatalf("expected credentials, got none")
	}

	for _, c := range creds {
		if c.Type == "" || c.ID == "" || c.UserID == "" {
			t.Fatalf("incomplete credential details: %+v", c)
		}
	}

	detail, err := adm.LookupUser(ctx, adminPrincipal, userRes.User.ID)
	if err != nil {
		t.Fatalf("LookupUser failed: %v", err)
	}
	if len(detail.Credentials) == 0 {
		t.Fatalf("expected credentials in detail")
	}
}

func TestAdmin_Security_AuditEvents(t *testing.T) {
	ctx := context.Background()
	ad := adaptermem.New()
	cCache := corecache.New()

	var eventsEmitted []auth.Event
	adminModule := admin.New()

	a, err := auth.New(auth.Config{
		Adapter: ad,
		Cache:   cCache,
		Plugins: []auth.PluginModule{adminModule},
	})
	if err != nil {
		t.Fatalf("auth.New failed: %v", err)
	}

	a.Events().SubscribeAll(func(ctx context.Context, e auth.Event) {
		eventsEmitted = append(eventsEmitted, e)
	})

	adm, err := auth.Get[plugins.Admin](a)
	if err != nil {
		t.Fatalf("auth.Get failed: %v", err)
	}

	adminRes, _ := a.SignUp(ctx, auth.SignUpInput{Email: "admin_audit@example.com", Password: "Password123!"})
	adminPrincipal := adminRes.Principal()
	_ = bootstrapAdmin(ctx, ad, adminPrincipal.Subject, "admin_audit@example.com")

	userRes, _ := a.SignUp(ctx, auth.SignUpInput{Email: "target_audit@example.com", Password: "Password123!"})

	// Disable user
	_ = adm.DisableUser(ctx, adminPrincipal, userRes.User.ID, "audit test")

	var foundDisabledEvent bool
	for _, e := range eventsEmitted {
		if e.Name == admin.EventUserDisabled {
			foundDisabledEvent = true
			payload, ok := e.Payload.(admin.UserDisabledPayload)
			if !ok {
				t.Fatalf("unexpected payload type: %T", e.Payload)
			}
			if payload.ActorID != adminPrincipal.Subject || payload.TargetUserID != userRes.User.ID {
				t.Fatalf("unexpected event payload: %+v", payload)
			}
		}
	}

	if !foundDisabledEvent {
		t.Fatalf("expected admin.user.disabled event to be emitted")
	}
}

func TestAdmin_Organizations_ScopedAdministration(t *testing.T) {
	ctx := context.Background()
	ad := adaptermem.New()
	cCache := corecache.New()

	orgModule := orgplugin.New()
	adminModule := admin.New()

	a, err := auth.New(auth.Config{
		Adapter: ad,
		Cache:   cCache,
		Plugins: []auth.PluginModule{orgModule, adminModule},
	})
	if err != nil {
		t.Fatalf("auth.New failed: %v", err)
	}

	orgCap, err := auth.Get[orgplugin.Organization](a)
	if err != nil {
		t.Fatalf("failed to get Organization capability: %v", err)
	}

	_, err = auth.Get[plugins.Admin](a)
	if err != nil {
		t.Fatalf("failed to get Admin capability: %v", err)
	}

	adminWithOrg := admin.New(
		admin.WithOrganizations(orgCap),
	)
	a2, err := auth.New(auth.Config{
		Adapter: ad,
		Cache:   cCache,
		Plugins: []auth.PluginModule{orgModule, adminWithOrg},
	})
	if err != nil {
		t.Fatalf("auth.New failed: %v", err)
	}
	admWithOrg, _ := auth.Get[plugins.Admin](a2)

	// 1. Create Organization Owner and Member
	ownerRes, _ := a.SignUp(ctx, auth.SignUpInput{Email: "orgowner@example.com", Password: "Password123!"})
	memberRes, _ := a.SignUp(ctx, auth.SignUpInput{Email: "orgmember@example.com", Password: "Password123!"})
	outsiderRes, _ := a.SignUp(ctx, auth.SignUpInput{Email: "outsider@example.com", Password: "Password123!"})

	org, err := orgCap.CreateOrganization(ctx, orgplugin.CreateOrganizationInput{
		Name:    "Acme Corp",
		Slug:    "acme",
		OwnerID: ownerRes.User.ID,
	})
	if err != nil {
		t.Fatalf("CreateOrganization failed: %v", err)
	}

	_, err = orgCap.AddMember(ctx, orgplugin.AddMemberInput{
		OrganizationID: org.ID,
		UserID:         memberRes.User.ID,
		Role:           orgplugin.RoleMember,
	})
	if err != nil {
		t.Fatalf("AddMember failed: %v", err)
	}

	// 2. Scoped Admin for Acme Corp
	scoped := admWithOrg.ForOrg(org.ID)

	// Owner acts with organization-scoped context
	ownerPrincipal := auth.Principal{Subject: ownerRes.User.ID, Type: auth.PrincipalUser}
	ctxWithPrincipal := auth.WithPrincipal(ctx, ownerPrincipal)

	// Lookup member should succeed
	memberDetail, err := scoped.LookupUser(ctxWithPrincipal, ownerPrincipal, memberRes.User.ID)
	if err != nil {
		t.Fatalf("Scoped LookupUser failed: %v", err)
	}
	if memberDetail.User.Email != "orgmember@example.com" {
		t.Fatalf("unexpected member email: %s", memberDetail.User.Email)
	}

	// Lookup outsider should fail with ErrUserNotInOrganization
	_, err = scoped.LookupUser(ctxWithPrincipal, ownerPrincipal, outsiderRes.User.ID)
	if !errors.Is(err, admin.ErrUserNotInOrganization) {
		t.Fatalf("expected ErrUserNotInOrganization for outsider, got %v", err)
	}

	// Member attempting scoped admin action should fail with ErrUnauthorized
	memberPrincipal := auth.Principal{Subject: memberRes.User.ID, Type: auth.PrincipalUser}
	ctxMember := auth.WithPrincipal(ctx, memberPrincipal)
	_, err = scoped.LookupUser(ctxMember, memberPrincipal, ownerRes.User.ID)
	if !errors.Is(err, admin.ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized for non-admin member, got %v", err)
	}
}
