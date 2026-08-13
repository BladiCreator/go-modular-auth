package admin_test

import (
	"context"
	"testing"
	"time"

	"github.com/BladiCreator/go-modular-auth/adapters/memory"
	"github.com/BladiCreator/go-modular-auth/auth"
	"github.com/BladiCreator/go-modular-auth/config"
	"github.com/BladiCreator/go-modular-auth/domain/dto"
	"github.com/BladiCreator/go-modular-auth/plugins"
	"github.com/BladiCreator/go-modular-auth/plugins/admin"
)

func setupAdminTest(t *testing.T, opts ...admin.Option) (*auth.Auth, *admin.Plugin, *memory.Store) {
	t.Helper()
	store := memory.New()

	adminPlugin := plugins.Admin(store, opts...)
	app, err := auth.New(
		config.WithPlugins(adminPlugin),
	)
	if err != nil {
		t.Fatalf("failed to initialize auth app: %v", err)
	}

	p := auth.Plugin[admin.Plugin](app)
	return app, p, store
}

func TestAdminPlugin_CreateUser(t *testing.T) {
	ctx := context.Background()
	app, p, _ := setupAdminTest(t)

	var eventReceived *admin.UserCreatedEventPayload
	app.Events().Subscribe(admin.EventUserCreated, func(payload *admin.UserCreatedEventPayload) {
		eventReceived = payload
	})

	adminCaller := admin.CallerContext{UserID: "admin_1", Role: admin.RoleAdmin}
	userCaller := admin.CallerContext{UserID: "user_1", Role: admin.RoleUser}

	t.Run("Forbidden for regular user", func(t *testing.T) {
		_, err := p.CreateUser(ctx, admin.CreateUserParams{
			Caller: userCaller,
			Name:   "Test User",
			Email:  "test@example.com",
		})
		if err != admin.ErrForbidden {
			t.Errorf("expected ErrForbidden, got %v", err)
		}
	})

	t.Run("Invalid email validation", func(t *testing.T) {
		_, err := p.CreateUser(ctx, admin.CreateUserParams{
			Caller: adminCaller,
			Name:   "Invalid Email",
			Email:  "not-an-email",
		})
		if err != admin.ErrInvalidEmail {
			t.Errorf("expected ErrInvalidEmail, got %v", err)
		}
	})

	t.Run("Password too short", func(t *testing.T) {
		_, err := p.CreateUser(ctx, admin.CreateUserParams{
			Caller:   adminCaller,
			Name:     "Short Pass",
			Email:    "short@example.com",
			Password: "123",
		})
		if err != admin.ErrPasswordTooShort {
			t.Errorf("expected ErrPasswordTooShort, got %v", err)
		}
	})

	t.Run("Successful creation with password and event emission", func(t *testing.T) {
		user, err := p.CreateUser(ctx, admin.CreateUserParams{
			Caller:   adminCaller,
			Name:     "John Doe",
			Email:    "john@example.com",
			Password: "Password123!",
			Role:     "user",
		})
		if err != nil {
			t.Fatalf("failed to create user: %v", err)
		}

		if user.Email != "john@example.com" {
			t.Errorf("expected email john@example.com, got %s", user.Email)
		}
		if user.Role != "user" {
			t.Errorf("expected role user, got %s", user.Role)
		}
		if user.Banned {
			t.Errorf("expected new user to not be banned")
		}

		time.Sleep(50 * time.Millisecond)
		if eventReceived == nil || eventReceived.User == nil || eventReceived.User.ID != user.ID {
			t.Errorf("expected EventUserCreated to be dispatched with created user")
		}
	})

	t.Run("Duplicate email rejection", func(t *testing.T) {
		_, err := p.CreateUser(ctx, admin.CreateUserParams{
			Caller: adminCaller,
			Name:   "Duplicate",
			Email:  "john@example.com",
		})
		if err != admin.ErrUserAlreadyExists {
			t.Errorf("expected ErrUserAlreadyExists, got %v", err)
		}
	})
}

func TestAdminPlugin_GetUser_And_ListUsers(t *testing.T) {
	ctx := context.Background()
	_, p, store := setupAdminTest(t)

	adminCaller := admin.CallerContext{UserID: "admin_1", Role: admin.RoleAdmin}
	userCaller := admin.CallerContext{UserID: "user_1", Role: admin.RoleUser}

	// Seed users
	u1, _ := store.CreateUser(ctx, &dto.CreateUserParams{Name: "Alice Wonderland", Email: "alice@example.com", Role: "user"})
	u2, _ := store.CreateUser(ctx, &dto.CreateUserParams{Name: "Bob Builder", Email: "bob@example.com", Role: "editor"})
	u3, _ := store.CreateUser(ctx, &dto.CreateUserParams{Name: "Charlie Chaplin", Email: "charlie@example.com", Role: "admin"})

	t.Run("GetUser forbidden for regular user", func(t *testing.T) {
		_, err := p.GetUser(ctx, admin.GetUserParams{
			Caller: userCaller,
			UserID: u1.ID,
		})
		if err != admin.ErrForbidden {
			t.Errorf("expected ErrForbidden, got %v", err)
		}
	})

	t.Run("GetUser success for admin", func(t *testing.T) {
		fetched, err := p.GetUser(ctx, admin.GetUserParams{
			Caller: adminCaller,
			UserID: u1.ID,
		})
		if err != nil {
			t.Fatalf("failed to get user: %v", err)
		}
		if fetched.Email != "alice@example.com" {
			t.Errorf("expected alice@example.com, got %s", fetched.Email)
		}
	})

	t.Run("ListUsers all users with sorting", func(t *testing.T) {
		res, err := p.ListUsers(ctx, admin.ListUsersParams{
			Caller: adminCaller,
			Filter: admin.ListUsersFilter{
				SortBy:        "email",
				SortDirection: "asc",
			},
		})
		if err != nil {
			t.Fatalf("failed to list users: %v", err)
		}
		if res.Total != 3 {
			t.Errorf("expected 3 total users, got %d", res.Total)
		}
		if res.Users[0].Email != "alice@example.com" {
			t.Errorf("expected first sorted user to be alice, got %s", res.Users[0].Email)
		}
	})

	t.Run("ListUsers filter by role", func(t *testing.T) {
		res, err := p.ListUsers(ctx, admin.ListUsersParams{
			Caller: adminCaller,
			Filter: admin.ListUsersFilter{
				FilterField: "role",
				FilterValue: "editor",
			},
		})
		if err != nil {
			t.Fatalf("failed to filter users: %v", err)
		}
		if res.Total != 1 || res.Users[0].ID != u2.ID {
			t.Errorf("expected only Bob Builder, got %d users", res.Total)
		}
	})

	t.Run("ListUsers search by keyword and pagination", func(t *testing.T) {
		res, err := p.ListUsers(ctx, admin.ListUsersParams{
			Caller: adminCaller,
			Filter: admin.ListUsersFilter{
				SearchField:    "name",
				SearchValue:    "Char",
				SearchOperator: "starts_with",
				Limit:          1,
				Offset:         0,
			},
		})
		if err != nil {
			t.Fatalf("failed to search users: %v", err)
		}
		if len(res.Users) != 1 || res.Users[0].ID != u3.ID {
			t.Errorf("expected Charlie Chaplin, got %v", res.Users)
		}
	})
}

func TestAdminPlugin_UpdateUser(t *testing.T) {
	ctx := context.Background()
	app, p, store := setupAdminTest(t)

	var eventReceived *admin.UserUpdatedEventPayload
	app.Events().Subscribe(admin.EventUserUpdated, func(payload *admin.UserUpdatedEventPayload) {
		eventReceived = payload
	})

	adminCaller := admin.CallerContext{UserID: "admin_1", Role: admin.RoleAdmin}
	u, _ := store.CreateUser(ctx, &dto.CreateUserParams{Name: "Old Name", Email: "old@example.com", Role: "user"})

	t.Run("ErrNoDataToUpdate when empty parameters provided", func(t *testing.T) {
		_, err := p.UpdateUser(ctx, admin.UpdateUserParams{
			Caller: adminCaller,
			UserID: u.ID,
		})
		if err != admin.ErrNoDataToUpdate {
			t.Errorf("expected ErrNoDataToUpdate, got %v", err)
		}
	})

	t.Run("Update name and email verified status successfully", func(t *testing.T) {
		newName := "New Name"
		verified := true
		updated, err := p.UpdateUser(ctx, admin.UpdateUserParams{
			Caller:        adminCaller,
			UserID:        u.ID,
			Name:          &newName,
			EmailVerified: &verified,
		})
		if err != nil {
			t.Fatalf("failed to update user: %v", err)
		}

		if updated.Name != "New Name" {
			t.Errorf("expected name 'New Name', got %s", updated.Name)
		}
		if !updated.EmailVerified {
			t.Errorf("expected EmailVerified to be true")
		}

		time.Sleep(50 * time.Millisecond)
		if eventReceived == nil || eventReceived.User.Name != "New Name" {
			t.Errorf("expected EventUserUpdated to be dispatched with updated profile")
		}
	})
}

func TestAdminPlugin_RemoveUser(t *testing.T) {
	ctx := context.Background()
	app, p, store := setupAdminTest(t)

	var eventReceived *admin.UserDeletedEventPayload
	app.Events().Subscribe(admin.EventUserDeleted, func(payload *admin.UserDeletedEventPayload) {
		eventReceived = payload
	})

	adminCaller := admin.CallerContext{UserID: "admin_1", Role: admin.RoleAdmin}
	u, _ := store.CreateUser(ctx, &dto.CreateUserParams{Name: "To Delete", Email: "delete@example.com", Role: "user"})

	t.Run("Cannot delete self", func(t *testing.T) {
		err := p.RemoveUser(ctx, admin.RemoveUserParams{
			Caller: adminCaller,
			UserID: "admin_1",
		})
		if err != admin.ErrCannotDeleteSelf {
			t.Errorf("expected ErrCannotDeleteSelf, got %v", err)
		}
	})

	t.Run("Successful user deletion", func(t *testing.T) {
		err := p.RemoveUser(ctx, admin.RemoveUserParams{
			Caller: adminCaller,
			UserID: u.ID,
		})
		if err != nil {
			t.Fatalf("failed to delete user: %v", err)
		}

		_, err = store.GetUserByID(ctx, u.ID)
		if err == nil {
			t.Errorf("expected user to be deleted from store")
		}

		time.Sleep(50 * time.Millisecond)
		if eventReceived == nil || eventReceived.UserID != u.ID {
			t.Errorf("expected EventUserDeleted to be dispatched")
		}
	})
}

func TestAdminPlugin_SetRole(t *testing.T) {
	ctx := context.Background()
	app, p, store := setupAdminTest(t)

	var eventReceived *admin.UserRoleChangedEventPayload
	app.Events().Subscribe(admin.EventUserRoleChanged, func(payload *admin.UserRoleChangedEventPayload) {
		eventReceived = payload
	})

	adminCaller := admin.CallerContext{UserID: "admin_1", Role: admin.RoleAdmin}
	u, _ := store.CreateUser(ctx, &dto.CreateUserParams{Name: "Role Tester", Email: "role@example.com", Role: "user"})

	t.Run("Assign invalid role", func(t *testing.T) {
		_, err := p.SetRole(ctx, admin.SetRoleParams{
			Caller: adminCaller,
			UserID: u.ID,
			Role:   "unknown_role",
		})
		if err != admin.ErrInvalidRole {
			t.Errorf("expected ErrInvalidRole, got %v", err)
		}
	})

	t.Run("Assign valid admin role", func(t *testing.T) {
		updated, err := p.SetRole(ctx, admin.SetRoleParams{
			Caller: adminCaller,
			UserID: u.ID,
			Role:   admin.RoleAdmin,
		})
		if err != nil {
			t.Fatalf("failed to set role: %v", err)
		}
		if updated.Role != admin.RoleAdmin {
			t.Errorf("expected role 'admin', got %s", updated.Role)
		}

		time.Sleep(50 * time.Millisecond)
		if eventReceived == nil || eventReceived.NewRole != admin.RoleAdmin || eventReceived.OldRole != "user" {
			t.Errorf("expected EventUserRoleChanged with old role 'user' and new role 'admin'")
		}
	})
}

func TestAdminPlugin_SetUserPassword(t *testing.T) {
	ctx := context.Background()
	app, p, store := setupAdminTest(t)

	var eventReceived *admin.UserPasswordChangedEventPayload
	app.Events().Subscribe(admin.EventUserPasswordChanged, func(payload *admin.UserPasswordChangedEventPayload) {
		eventReceived = payload
	})

	adminCaller := admin.CallerContext{UserID: "admin_1", Role: admin.RoleAdmin}
	u, _ := store.CreateUser(ctx, &dto.CreateUserParams{Name: "Password Tester", Email: "pass@example.com", Role: "user"})

	t.Run("Password too short", func(t *testing.T) {
		err := p.SetUserPassword(ctx, admin.SetUserPasswordParams{
			Caller:      adminCaller,
			UserID:      u.ID,
			NewPassword: "123",
		})
		if err != admin.ErrPasswordTooShort {
			t.Errorf("expected ErrPasswordTooShort, got %v", err)
		}
	})

	t.Run("Set password successfully", func(t *testing.T) {
		err := p.SetUserPassword(ctx, admin.SetUserPasswordParams{
			Caller:      adminCaller,
			UserID:      u.ID,
			NewPassword: "BrandNewSecurePassword123!",
		})
		if err != nil {
			t.Fatalf("failed to set password: %v", err)
		}

		acc, err := store.GetAccountByUserIDAndProvider(ctx, u.ID, "credential")
		if err != nil {
			t.Fatalf("failed to find credential account: %v", err)
		}
		if acc.Password == "" {
			t.Errorf("expected password hash to be stored")
		}

		time.Sleep(50 * time.Millisecond)
		if eventReceived == nil || eventReceived.UserID != u.ID {
			t.Errorf("expected EventUserPasswordChanged to be dispatched")
		}
	})
}

func TestAdminPlugin_ModerationAndBans(t *testing.T) {
	ctx := context.Background()
	app, p, store := setupAdminTest(t)

	var bannedEvent *admin.UserBannedEventPayload
	var unbannedEvent *admin.UserUnbannedEventPayload

	app.Events().Subscribe(admin.EventUserBanned, func(payload *admin.UserBannedEventPayload) {
		bannedEvent = payload
	})
	app.Events().Subscribe(admin.EventUserUnbanned, func(payload *admin.UserUnbannedEventPayload) {
		unbannedEvent = payload
	})

	adminCaller := admin.CallerContext{UserID: "admin_1", Role: admin.RoleAdmin}
	u, _ := store.CreateUser(ctx, &dto.CreateUserParams{Name: "Troublemaker", Email: "banme@example.com", Role: "user"})

	// Create active session for the user
	sess, err := store.CreateSession(ctx, &dto.CreateSessionParams{
		UserID:    u.ID,
		Token:     "active-session-token",
		ExpiresAt: time.Now().Add(24 * time.Hour),
		CreatedAt: time.Now(),
	})
	if err != nil {
		t.Fatalf("failed to seed session: %v", err)
	}

	t.Run("Cannot ban self", func(t *testing.T) {
		_, err := p.BanUser(ctx, admin.BanUserParams{
			Caller: adminCaller,
			UserID: "admin_1",
		})
		if err != admin.ErrCannotBanSelf {
			t.Errorf("expected ErrCannotBanSelf, got %v", err)
		}
	})

	t.Run("Ban user and automatically invalidate active sessions", func(t *testing.T) {
		dur := 2 * time.Hour
		bannedUser, err := p.BanUser(ctx, admin.BanUserParams{
			Caller:       adminCaller,
			UserID:       u.ID,
			BanReason:    "Spamming system",
			BanExpiresIn: &dur,
		})
		if err != nil {
			t.Fatalf("failed to ban user: %v", err)
		}
		if !bannedUser.Banned {
			t.Errorf("expected user to be banned")
		}
		if bannedUser.BanReason == nil || *bannedUser.BanReason != "Spamming system" {
			t.Errorf("expected ban reason to be 'Spamming system'")
		}
		if bannedUser.BanExpires == nil {
			t.Errorf("expected ban expiration to be set")
		}

		// Verify session was revoked
		_, err = store.GetSessionByToken(ctx, sess.Token)
		if err == nil {
			t.Errorf("expected active session to be revoked upon ban")
		}

		// Verify ban hook returns error
		if err := p.CheckUserBanStatus(ctx, bannedUser); err != admin.ErrUserBanned {
			t.Errorf("expected CheckUserBanStatus to return ErrUserBanned, got %v", err)
		}

		time.Sleep(50 * time.Millisecond)
		if bannedEvent == nil || bannedEvent.UserID != u.ID {
			t.Errorf("expected EventUserBanned to be dispatched")
		}
	})

	t.Run("Automatic unban on expired suspension", func(t *testing.T) {
		past := time.Now().Add(-10 * time.Minute)
		u.Banned = true
		u.BanExpires = &past

		err := p.CheckUserBanStatus(ctx, u)
		if err != nil {
			t.Errorf("expected expired ban to return nil and lift suspension, got %v", err)
		}
		if u.Banned {
			t.Errorf("expected user to be automatically unbanned")
		}
	})

	t.Run("Explicit unban", func(t *testing.T) {
		u.Banned = true
		_ = store.UpdateUser(ctx, u)

		unbannedUser, err := p.UnbanUser(ctx, admin.UnbanUserParams{
			Caller: adminCaller,
			UserID: u.ID,
		})
		if err != nil {
			t.Fatalf("failed to unban user: %v", err)
		}
		if unbannedUser.Banned {
			t.Errorf("expected user to not be banned")
		}

		time.Sleep(50 * time.Millisecond)
		if unbannedEvent == nil || unbannedEvent.UserID != u.ID {
			t.Errorf("expected EventUserUnbanned to be dispatched")
		}
	})
}

func TestAdminPlugin_Impersonation(t *testing.T) {
	ctx := context.Background()
	app, p, store := setupAdminTest(t)

	var impersonateEvent *admin.UserImpersonatedEventPayload
	var stopEvent *admin.ImpersonationStoppedEventPayload

	app.Events().Subscribe(admin.EventUserImpersonated, func(payload *admin.UserImpersonatedEventPayload) {
		impersonateEvent = payload
	})
	app.Events().Subscribe(admin.EventImpersonationStopped, func(payload *admin.ImpersonationStoppedEventPayload) {
		stopEvent = payload
	})

	adminUser, _ := store.CreateUser(ctx, &dto.CreateUserParams{Name: "Master Admin", Email: "admin@corp.com", Role: "admin"})
	regularUser, _ := store.CreateUser(ctx, &dto.CreateUserParams{Name: "Target User", Email: "target@corp.com", Role: "user"})
	anotherAdmin, _ := store.CreateUser(ctx, &dto.CreateUserParams{Name: "Other Admin", Email: "admin2@corp.com", Role: "admin"})

	adminCaller := admin.CallerContext{
		UserID: adminUser.ID,
		Role:   admin.RoleAdmin,
		Extra:  map[string]any{admin.ExtraKeyAdminSession: "admin-secret-session-token"},
	}

	t.Run("Cannot impersonate self", func(t *testing.T) {
		_, err := p.ImpersonateUser(ctx, admin.ImpersonateUserParams{
			Caller: adminCaller,
			UserID: adminUser.ID,
		})
		if err != admin.ErrCannotImpersonateSelf {
			t.Errorf("expected ErrCannotImpersonateSelf, got %v", err)
		}
	})

	t.Run("Cannot impersonate another admin by default", func(t *testing.T) {
		_, err := p.ImpersonateUser(ctx, admin.ImpersonateUserParams{
			Caller: adminCaller,
			UserID: anotherAdmin.ID,
		})
		if err != admin.ErrCannotImpersonateAdmin {
			t.Errorf("expected ErrCannotImpersonateAdmin, got %v", err)
		}
	})

	t.Run("Impersonate regular user successfully", func(t *testing.T) {
		dur := 30 * time.Minute
		res, err := p.ImpersonateUser(ctx, admin.ImpersonateUserParams{
			Caller:    adminCaller,
			UserID:    regularUser.ID,
			Duration:  &dur,
			IPAddress: "192.168.1.100",
			UserAgent: "Mozilla/5.0",
		})
		if err != nil {
			t.Fatalf("failed to impersonate user: %v", err)
		}

		if res.Session == nil || res.Session.Token == "" {
			t.Fatalf("expected active masquerade session to be generated")
		}
		if res.Session.ImpersonatedBy == nil || *res.Session.ImpersonatedBy != adminUser.ID {
			t.Errorf("expected ImpersonatedBy to match adminUser.ID")
		}
		if res.User.ID != regularUser.ID {
			t.Errorf("expected target user details in response")
		}

		time.Sleep(50 * time.Millisecond)
		if impersonateEvent == nil || impersonateEvent.TargetUserID != regularUser.ID {
			t.Errorf("expected EventUserImpersonated to be dispatched")
		}

		// Stop impersonating
		stopRes, err := p.StopImpersonating(ctx, admin.StopImpersonatingParams{
			ImpersonatedSessionToken: res.Session.Token,
		})
		if err != nil {
			t.Fatalf("failed to stop impersonating: %v", err)
		}
		if stopRes.AdminUser.ID != adminUser.ID {
			t.Errorf("expected restored admin user to be adminUser.ID")
		}

		// Verify masquerade session is revoked
		_, err = store.GetSessionByToken(ctx, res.Session.Token)
		if err == nil {
			t.Errorf("expected impersonated session to be revoked after stopping")
		}

		time.Sleep(50 * time.Millisecond)
		if stopEvent == nil || stopEvent.AdminUserID != adminUser.ID {
			t.Errorf("expected EventImpersonationStopped to be dispatched")
		}
	})
}

func TestAdminPlugin_SessionManagement(t *testing.T) {
	ctx := context.Background()
	app, p, store := setupAdminTest(t)

	var sessionRevokedEvent *admin.SessionRevokedEventPayload
	var allSessionsRevokedEvent *admin.AllSessionsRevokedEventPayload

	app.Events().Subscribe(admin.EventSessionRevoked, func(payload *admin.SessionRevokedEventPayload) {
		sessionRevokedEvent = payload
	})
	app.Events().Subscribe(admin.EventAllSessionsRevoked, func(payload *admin.AllSessionsRevokedEventPayload) {
		allSessionsRevokedEvent = payload
	})

	adminCaller := admin.CallerContext{UserID: "admin_1", Role: admin.RoleAdmin}
	u, _ := store.CreateUser(ctx, &dto.CreateUserParams{Name: "Session User", Email: "sess@corp.com", Role: "user"})

	s1, _ := store.CreateSession(ctx, &dto.CreateSessionParams{UserID: u.ID, Token: "tok-1", ExpiresAt: time.Now().Add(1 * time.Hour), CreatedAt: time.Now()})
	s2, _ := store.CreateSession(ctx, &dto.CreateSessionParams{UserID: u.ID, Token: "tok-2", ExpiresAt: time.Now().Add(2 * time.Hour), CreatedAt: time.Now()})

	t.Run("ListUserSessions", func(t *testing.T) {
		sessions, err := p.ListUserSessions(ctx, admin.ListUserSessionsParams{
			Caller: adminCaller,
			UserID: u.ID,
		})
		if err != nil {
			t.Fatalf("failed to list user sessions: %v", err)
		}
		if len(sessions) != 2 {
			t.Errorf("expected 2 active sessions, got %d", len(sessions))
		}
	})

	t.Run("RevokeUserSession single", func(t *testing.T) {
		err := p.RevokeUserSession(ctx, admin.RevokeUserSessionParams{
			Caller:       adminCaller,
			SessionToken: s1.Token,
		})
		if err != nil {
			t.Fatalf("failed to revoke session: %v", err)
		}

		_, err = store.GetSessionByToken(ctx, s1.Token)
		if err == nil {
			t.Errorf("expected tok-1 to be deleted")
		}

		time.Sleep(50 * time.Millisecond)
		if sessionRevokedEvent == nil || sessionRevokedEvent.SessionToken != s1.Token {
			t.Errorf("expected EventSessionRevoked to be dispatched")
		}
	})

	t.Run("RevokeUserSessions all", func(t *testing.T) {
		err := p.RevokeUserSessions(ctx, admin.RevokeUserSessionsParams{
			Caller: adminCaller,
			UserID: u.ID,
		})
		if err != nil {
			t.Fatalf("failed to revoke all sessions: %v", err)
		}

		_, err = store.GetSessionByToken(ctx, s2.Token)
		if err == nil {
			t.Errorf("expected tok-2 to be deleted")
		}

		time.Sleep(50 * time.Millisecond)
		if allSessionsRevokedEvent == nil || allSessionsRevokedEvent.UserID != u.ID {
			t.Errorf("expected EventAllSessionsRevoked to be dispatched")
		}
	})
}
