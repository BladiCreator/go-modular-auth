package audit_test

import (
	"context"
	"testing"
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	adaptermem "github.com/BladiCreator/go-modular-auth/adapter/memory"
	corecache "github.com/BladiCreator/go-modular-auth/cache/memory"
	audit "github.com/BladiCreator/go-modular-auth/plugins/audit"
	"github.com/BladiCreator/go-modular-auth/plugins/audit/plugins"
	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

func setupTestAuth(t *testing.T, opts ...audit.Option) (*auth.Auth, plugins.Audit) {
	t.Helper()
	ad := adaptermem.New()
	cCache := corecache.New()

	audModule := audit.New(opts...)

	a, err := auth.New(auth.Config{
		Adapter: ad,
		Cache:   cCache,
		Plugins: []auth.PluginModule{audModule},
	})
	if err != nil {
		t.Fatalf("auth.New failed: %v", err)
	}

	t.Cleanup(func() {
		_ = a.Close(context.Background())
	})

	audCap, err := auth.Get[plugins.Audit](a)
	if err != nil {
		t.Fatalf("auth.Get[plugins.Audit] failed: %v", err)
	}

	return a, audCap
}

func TestAudit_CoreEvents_Consumed(t *testing.T) {
	ctx := context.Background()
	a, audCap := setupTestAuth(t)

	// 1. SignUp triggers user.created
	signupRes, err := a.SignUp(ctx, auth.SignUpInput{
		Email:    "alice@example.com",
		Password: "Password123!",
	})
	if err != nil {
		t.Fatalf("SignUp failed: %v", err)
	}
	userID := signupRes.User.ID

	// Query audit records for this user
	records, err := audCap.QueryByActor(ctx, userID, 10)
	if err != nil {
		t.Fatalf("QueryByActor failed: %v", err)
	}
	if len(records) == 0 {
		t.Fatalf("expected at least 1 audit record for user %s, got 0", userID)
	}

	foundUserCreated := false
	for _, r := range records {
		if r.Event == string(auth.EventUserCreated) {
			foundUserCreated = true
			if r.ActorSubject != userID {
				t.Errorf("expected ActorSubject %s, got %s", userID, r.ActorSubject)
			}
			if r.Outcome != audit.OutcomeSuccess {
				t.Errorf("expected OutcomeSuccess, got %s", r.Outcome)
			}
			if r.TargetID != userID {
				t.Errorf("expected TargetID %s, got %s", userID, r.TargetID)
			}
		}
	}
	if !foundUserCreated {
		t.Fatalf("expected to find user.created event in audit log")
	}

	// 2. SignIn triggers user.signed_in and session.created
	signinRes, err := a.SignIn(ctx, auth.SignInInput{
		Email:    "alice@example.com",
		Password: "Password123!",
	})
	if err != nil {
		t.Fatalf("SignIn failed: %v", err)
	}

	// 3. SignOut triggers user.signed_out
	err = a.SignOut(ctx, auth.SignOutInput{Token: signinRes.Token})
	if err != nil {
		t.Fatalf("SignOut failed: %v", err)
	}

	// Verify all records captured
	res, err := audCap.Query(ctx, audit.ListFilter{
		ActorSubject: userID,
	})
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}

	// We expect user.created, session.created, user.signed_in, session.revoked, user.signed_out
	if len(res.Records) < 3 {
		t.Fatalf("expected at least 3 audit records, got %d", len(res.Records))
	}
}

func TestAudit_ManualRecord_AndQueries(t *testing.T) {
	ctx := context.Background()
	_, audCap := setupTestAuth(t)

	// Record custom administrative event
	customRecord := &audit.AuditRecord{
		Event:          "admin.permission.granted",
		Action:         "permission.grant",
		ActorSubject:   "admin_user_42",
		ActorType:      "user",
		TargetType:     "user",
		TargetID:       "target_user_99",
		Outcome:        audit.OutcomeSuccess,
		OrganizationID: "org_acme_corp",
		IPAddress:      "203.0.113.195",
		UserAgent:      "Mozilla/5.0 (AdminPortal/1.0)",
		Metadata: map[string]any{
			"role":        "security_auditor",
			"granted_by":  "superadmin",
			"valid_days":  30,
			"should_drop": "clean_value",
		},
	}

	err := audCap.Record(ctx, customRecord)
	if err != nil {
		t.Fatalf("Record failed: %v", err)
	}

	// 1. GetByID
	rec, err := audCap.GetByID(ctx, customRecord.ID)
	if err != nil {
		t.Fatalf("GetByID failed: %v", err)
	}
	if rec.ActorSubject != "admin_user_42" {
		t.Errorf("expected ActorSubject admin_user_42, got %s", rec.ActorSubject)
	}
	if rec.OrganizationID != "org_acme_corp" {
		t.Errorf("expected OrganizationID org_acme_corp, got %s", rec.OrganizationID)
	}

	// 2. QueryByTarget
	targetRecords, err := audCap.QueryByTarget(ctx, "user", "target_user_99", 5)
	if err != nil {
		t.Fatalf("QueryByTarget failed: %v", err)
	}
	if len(targetRecords) != 1 {
		t.Fatalf("expected 1 record for target, got %d", len(targetRecords))
	}

	// 3. QueryByOrganization
	orgRes, err := audCap.QueryByOrganization(ctx, "org_acme_corp", audit.ListFilter{})
	if err != nil {
		t.Fatalf("QueryByOrganization failed: %v", err)
	}
	if orgRes.Total != 1 {
		t.Fatalf("expected Total 1, got %d", orgRes.Total)
	}
	if orgRes.Records[0].Metadata["role"] != "security_auditor" {
		t.Fatalf("expected metadata role to be retained")
	}
}

func TestAudit_AsyncBufferProcessing(t *testing.T) {
	ctx := context.Background()
	_, audCap := setupTestAuth(t,
		audit.WithAsync(2, 50, 5, 20*time.Millisecond),
	)

	// Rapidly record 15 items
	for i := 0; i < 15; i++ {
		err := audCap.Record(ctx, &audit.AuditRecord{
			Event:        "system.heartbeat",
			ActorSubject: "system_daemon",
			Outcome:      audit.OutcomeSuccess,
		})
		if err != nil {
			t.Fatalf("Record failed: %v", err)
		}
	}

	// Wait for background worker ticker to flush
	time.Sleep(100 * time.Millisecond)

	res, err := audCap.Query(ctx, audit.ListFilter{
		Event: "system.heartbeat",
	})
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	if res.Total != 15 {
		t.Fatalf("expected 15 records in async store, got %d", res.Total)
	}
}

func TestAudit_GracefulShutdownThroughAuth(t *testing.T) {
	ctx := context.Background()
	a, audCap := setupTestAuth(t,
		audit.WithAsync(2, 50, 5, 10*time.Second), // 10s ticker: flush won't happen from ticker
	)

	for i := 0; i < 10; i++ {
		err := audCap.Record(ctx, &audit.AuditRecord{
			Event:        "shutdown.test",
			ActorSubject: "user_test",
			Outcome:      audit.OutcomeSuccess,
		})
		if err != nil {
			t.Fatalf("Record failed: %v", err)
		}
	}

	// Calling a.Close(ctx) must gracefully flush all pending records immediately!
	if err := a.Close(ctx); err != nil {
		t.Fatalf("a.Close failed: %v", err)
	}

	res, err := audCap.Query(ctx, audit.ListFilter{
		Event: "shutdown.test",
	})
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	if res.Total != 10 {
		t.Fatalf("expected 10 records after graceful shutdown flush, got %d", res.Total)
	}
}
