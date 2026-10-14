package organizations_test

import (
	"context"
	"testing"
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	"github.com/BladiCreator/go-modular-auth-organizations"
	"github.com/BladiCreator/go-modular-auth-organizations/plugins"
	adaptermem "github.com/BladiCreator/go-modular-auth/adapter/memory"
)

func setupTestApp(t *testing.T) (*auth.Auth, organizations.Organization) {
	t.Helper()

	orgModule := organizations.New(
		organizations.WithCacheTTL(10*time.Minute),
	)

	a, err := auth.New(auth.Config{
		Adapter: adaptermem.New(),
		Plugins: []auth.PluginModule{orgModule},
	})
	if err != nil {
		t.Fatalf("auth.New failed: %v", err)
	}

	// Test retrieval via plugins.Organization
	orgs, err := auth.Get[plugins.Organization](a)
	if err != nil {
		t.Fatalf("auth.Get[plugins.Organization] failed: %v", err)
	}

	// Test retrieval via organizations.Organization
	_, err = auth.Get[organizations.Organization](a)
	if err != nil {
		t.Fatalf("auth.Get[organizations.Organization] failed: %v", err)
	}

	return a, orgs
}

func TestOrganizationLifecycle(t *testing.T) {
	ctx := context.Background()
	_, orgs := setupTestApp(t)

	// 1. Create Organization
	created, err := orgs.CreateOrganization(ctx, organizations.CreateOrganizationInput{
		Name:    "Acme Corp",
		Slug:    "acme",
		OwnerID: "user_owner_1",
		Metadata: map[string]string{
			"plan": "enterprise",
		},
	})
	if err != nil {
		t.Fatalf("CreateOrganization failed: %v", err)
	}
	if created.ID == "" || created.Slug != "acme" || created.OwnerID != "user_owner_1" {
		t.Errorf("Unexpected created organization: %+v", created)
	}

	// Verify owner is added as active member with RoleOwner
	mem, err := orgs.GetMember(ctx, created.ID, "user_owner_1")
	if err != nil {
		t.Fatalf("GetMember for owner failed: %v", err)
	}
	if mem.Role != organizations.RoleOwner || mem.Status != organizations.MembershipActive {
		t.Errorf("Owner membership invalid: role=%s status=%s", mem.Role, mem.Status)
	}

	// 2. Reject duplicate slug
	_, err = orgs.CreateOrganization(ctx, organizations.CreateOrganizationInput{
		Name:    "Acme Duplicate",
		Slug:    "acme",
		OwnerID: "user_owner_2",
	})
	if err == nil {
		t.Fatal("Expected conflict error for duplicate slug, got nil")
	}

	// 3. Get by ID and Slug
	byID, err := orgs.GetOrganization(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetOrganization by ID failed: %v", err)
	}
	if byID.Name != "Acme Corp" {
		t.Errorf("Expected Name 'Acme Corp', got %s", byID.Name)
	}

	bySlug, err := orgs.GetOrganizationBySlug(ctx, "acme")
	if err != nil {
		t.Fatalf("GetOrganizationBySlug failed: %v", err)
	}
	if bySlug.ID != created.ID {
		t.Errorf("Expected ID %s, got %s", created.ID, bySlug.ID)
	}

	// 4. Update
	newName := "Acme Corporation"
	updated, err := orgs.UpdateOrganization(ctx, created.ID, organizations.UpdateOrganizationInput{
		Name: &newName,
	})
	if err != nil {
		t.Fatalf("UpdateOrganization failed: %v", err)
	}
	if updated.Name != "Acme Corporation" {
		t.Errorf("Expected updated name 'Acme Corporation', got %s", updated.Name)
	}

	// 5. ListUserOrganizations
	userOrgs, err := orgs.ListUserOrganizations(ctx, "user_owner_1")
	if err != nil {
		t.Fatalf("ListUserOrganizations failed: %v", err)
	}
	if len(userOrgs) != 1 || userOrgs[0].ID != created.ID {
		t.Errorf("Expected 1 organization for owner, got %d", len(userOrgs))
	}

	// 6. Delete Organization
	if err := orgs.DeleteOrganization(ctx, created.ID); err != nil {
		t.Fatalf("DeleteOrganization failed: %v", err)
	}

	_, err = orgs.GetOrganization(ctx, created.ID)
	if err == nil {
		t.Fatal("Expected error fetching deleted organization, got nil")
	}
}

func TestOwnershipTransfer(t *testing.T) {
	ctx := context.Background()
	_, orgs := setupTestApp(t)

	org, err := orgs.CreateOrganization(ctx, organizations.CreateOrganizationInput{
		Name:    "Beta Tech",
		Slug:    "beta-tech",
		OwnerID: "user_1",
	})
	if err != nil {
		t.Fatalf("CreateOrganization failed: %v", err)
	}

	// Add member user_2
	_, err = orgs.AddMember(ctx, organizations.AddMemberInput{
		OrganizationID: org.ID,
		UserID:         "user_2",
		Role:           organizations.RoleMember,
	})
	if err != nil {
		t.Fatalf("AddMember failed: %v", err)
	}

	// Transfer ownership to user_2
	if err := orgs.TransferOwnership(ctx, org.ID, "user_2"); err != nil {
		t.Fatalf("TransferOwnership failed: %v", err)
	}

	// Check org owner
	updatedOrg, err := orgs.GetOrganization(ctx, org.ID)
	if err != nil {
		t.Fatalf("GetOrganization failed: %v", err)
	}
	if updatedOrg.OwnerID != "user_2" {
		t.Errorf("Expected OwnerID 'user_2', got %s", updatedOrg.OwnerID)
	}

	// user_2 should be RoleOwner
	mem2, _ := orgs.GetMember(ctx, org.ID, "user_2")
	if mem2.Role != organizations.RoleOwner {
		t.Errorf("Expected user_2 to be owner, got %s", mem2.Role)
	}

	// user_1 should be demoted to RoleAdmin
	mem1, _ := orgs.GetMember(ctx, org.ID, "user_1")
	if mem1.Role != organizations.RoleAdmin {
		t.Errorf("Expected user_1 to be admin, got %s", mem1.Role)
	}

	// Cannot remove the new owner
	if err := orgs.RemoveMember(ctx, org.ID, "user_2"); err == nil {
		t.Fatal("Expected ErrCannotRemoveOwner, got nil")
	}
}

func TestMembershipManagement(t *testing.T) {
	ctx := context.Background()
	_, orgs := setupTestApp(t)

	org, _ := orgs.CreateOrganization(ctx, organizations.CreateOrganizationInput{
		Name:    "Gamma Corp",
		Slug:    "gamma",
		OwnerID: "owner_g",
	})

	// Add member
	m, err := orgs.AddMember(ctx, organizations.AddMemberInput{
		OrganizationID: org.ID,
		UserID:         "user_member",
		Role:           organizations.RoleMember,
	})
	if err != nil {
		t.Fatalf("AddMember failed: %v", err)
	}
	if m.Role != organizations.RoleMember || m.Status != organizations.MembershipActive {
		t.Errorf("Unexpected membership: %+v", m)
	}

	// Duplicate add
	_, err = orgs.AddMember(ctx, organizations.AddMemberInput{
		OrganizationID: org.ID,
		UserID:         "user_member",
		Role:           organizations.RoleMember,
	})
	if err == nil {
		t.Fatal("Expected duplicate member error, got nil")
	}

	// Update role
	updatedM, err := orgs.UpdateMemberRole(ctx, org.ID, "user_member", organizations.RoleAdmin)
	if err != nil {
		t.Fatalf("UpdateMemberRole failed: %v", err)
	}
	if updatedM.Role != organizations.RoleAdmin {
		t.Errorf("Expected role Admin, got %s", updatedM.Role)
	}

	// Suspend member
	suspendedM, err := orgs.UpdateMemberStatus(ctx, org.ID, "user_member", organizations.MembershipSuspended)
	if err != nil {
		t.Fatalf("UpdateMemberStatus failed: %v", err)
	}
	if suspendedM.Status != organizations.MembershipSuspended {
		t.Errorf("Expected status Suspended, got %s", suspendedM.Status)
	}

	// List members
	members, err := orgs.ListMembers(ctx, org.ID)
	if err != nil {
		t.Fatalf("ListMembers failed: %v", err)
	}
	if len(members) != 2 {
		t.Errorf("Expected 2 members, got %d", len(members))
	}

	// Remove member
	if err := orgs.RemoveMember(ctx, org.ID, "user_member"); err != nil {
		t.Fatalf("RemoveMember failed: %v", err)
	}

	_, err = orgs.GetMember(ctx, org.ID, "user_member")
	if err == nil {
		t.Fatal("Expected ErrMemberNotFound, got nil")
	}
}

func TestTeamManagement(t *testing.T) {
	ctx := context.Background()
	_, orgs := setupTestApp(t)

	org, _ := orgs.CreateOrganization(ctx, organizations.CreateOrganizationInput{
		Name:    "Delta Labs",
		Slug:    "delta",
		OwnerID: "owner_d",
	})

	_, _ = orgs.AddMember(ctx, organizations.AddMemberInput{
		OrganizationID: org.ID,
		UserID:         "eng_1",
		Role:           organizations.RoleMember,
	})

	// Create Team
	team, err := orgs.CreateTeam(ctx, organizations.CreateTeamInput{
		OrganizationID: org.ID,
		Name:           "Core Engineering",
		Slug:           "core-eng",
		Description:    "Backend core team",
	})
	if err != nil {
		t.Fatalf("CreateTeam failed: %v", err)
	}
	if team.Name != "Core Engineering" || team.Slug != "core-eng" {
		t.Errorf("Unexpected team: %+v", team)
	}

	// Add team member
	if err := orgs.AddTeamMember(ctx, org.ID, team.ID, "eng_1"); err != nil {
		t.Fatalf("AddTeamMember failed: %v", err)
	}

	// Adding non-org member to team must fail
	if err := orgs.AddTeamMember(ctx, org.ID, team.ID, "outsider"); err == nil {
		t.Fatal("Expected error adding non-member to team, got nil")
	}

	// List team members
	members, err := orgs.ListTeamMembers(ctx, org.ID, team.ID)
	if err != nil {
		t.Fatalf("ListTeamMembers failed: %v", err)
	}
	if len(members) != 1 || members[0] != "eng_1" {
		t.Errorf("Expected ['eng_1'], got %v", members)
	}

	// Remove team member
	if err := orgs.RemoveTeamMember(ctx, org.ID, team.ID, "eng_1"); err != nil {
		t.Fatalf("RemoveTeamMember failed: %v", err)
	}
	members, _ = orgs.ListTeamMembers(ctx, org.ID, team.ID)
	if len(members) != 0 {
		t.Errorf("Expected 0 team members, got %d", len(members))
	}

	// Delete Team
	if err := orgs.DeleteTeam(ctx, org.ID, team.ID); err != nil {
		t.Fatalf("DeleteTeam failed: %v", err)
	}
	_, err = orgs.GetTeam(ctx, org.ID, team.ID)
	if err == nil {
		t.Fatal("Expected ErrTeamNotFound, got nil")
	}
}

func TestInvitations(t *testing.T) {
	ctx := context.Background()
	_, orgs := setupTestApp(t)

	org, _ := orgs.CreateOrganization(ctx, organizations.CreateOrganizationInput{
		Name:    "Epsilon Ventures",
		Slug:    "epsilon",
		OwnerID: "owner_e",
	})

	// Create Invitation
	inv, token, err := orgs.CreateInvitation(ctx, organizations.CreateInvitationInput{
		OrganizationID: org.ID,
		Email:          "invitee@example.com",
		Role:           organizations.RoleMember,
		InviterUserID:  "owner_e",
		TTL:            24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("CreateInvitation failed: %v", err)
	}
	if token == "" || inv.TokenHash == "" {
		t.Fatal("Expected raw token and token hash")
	}

	// Accept Invitation
	acceptedMem, err := orgs.AcceptInvitation(ctx, token, "user_invitee")
	if err != nil {
		t.Fatalf("AcceptInvitation failed: %v", err)
	}
	if acceptedMem.UserID != "user_invitee" || acceptedMem.Role != organizations.RoleMember {
		t.Errorf("Unexpected accepted membership: %+v", acceptedMem)
	}

	// Replay / Double-redemption must fail
	_, err = orgs.AcceptInvitation(ctx, token, "user_invitee_2")
	if err == nil {
		t.Fatal("Expected ErrInvitationAlreadyAccepted on replay, got nil")
	}

	// Revoke Invitation test
	inv2, _, _ := orgs.CreateInvitation(ctx, organizations.CreateInvitationInput{
		OrganizationID: org.ID,
		Email:          "revokeme@example.com",
		Role:           organizations.RoleMember,
		InviterUserID:  "owner_e",
	})
	if err := orgs.RevokeInvitation(ctx, org.ID, inv2.ID); err != nil {
		t.Fatalf("RevokeInvitation failed: %v", err)
	}
	_, err = orgs.GetInvitation(ctx, org.ID, inv2.ID)
	if err == nil {
		t.Fatal("Expected ErrInvitationNotFound for revoked invitation, got nil")
	}
}

func TestAuthorization(t *testing.T) {
	ctx := context.Background()
	_, orgs := setupTestApp(t)

	org, _ := orgs.CreateOrganization(ctx, organizations.CreateOrganizationInput{
		Name:    "Zeta Cloud",
		Slug:    "zeta",
		OwnerID: "user_owner",
	})

	_, _ = orgs.AddMember(ctx, organizations.AddMemberInput{
		OrganizationID: org.ID,
		UserID:         "user_admin",
		Role:           organizations.RoleAdmin,
	})

	_, _ = orgs.AddMember(ctx, organizations.AddMemberInput{
		OrganizationID: org.ID,
		UserID:         "user_member",
		Role:           organizations.RoleMember,
	})

	// 1. Authorize Owner
	ownerCtx := auth.WithPrincipal(ctx, auth.Principal{Subject: "user_owner", Type: auth.PrincipalUser})
	if _, err := orgs.Authorize(ownerCtx, org.ID, organizations.RoleOwner); err != nil {
		t.Errorf("Owner failed RoleOwner check: %v", err)
	}
	if _, err := orgs.Authorize(ownerCtx, org.ID, organizations.RoleMember); err != nil {
		t.Errorf("Owner failed RoleMember check: %v", err)
	}

	// 2. Authorize Admin
	adminCtx := auth.WithPrincipal(ctx, auth.Principal{Subject: "user_admin", Type: auth.PrincipalUser})
	if _, err := orgs.Authorize(adminCtx, org.ID, organizations.RoleAdmin); err != nil {
		t.Errorf("Admin failed RoleAdmin check: %v", err)
	}
	// Admin trying to act as Owner must fail
	if _, err := orgs.Authorize(adminCtx, org.ID, organizations.RoleOwner); err == nil {
		t.Error("Admin passed RoleOwner check, expected error")
	}

	// 3. Authorize Member
	memberCtx := auth.WithPrincipal(ctx, auth.Principal{Subject: "user_member", Type: auth.PrincipalUser})
	if _, err := orgs.Authorize(memberCtx, org.ID, organizations.RoleMember); err != nil {
		t.Errorf("Member failed RoleMember check: %v", err)
	}
	if _, err := orgs.Authorize(memberCtx, org.ID, organizations.RoleAdmin); err == nil {
		t.Error("Member passed RoleAdmin check, expected error")
	}

	// 4. Cross-organization authorization prevention
	scopedWrongOrgCtx := organizations.WithOrganizationContext(ownerCtx, "other_org_id")
	if _, err := orgs.Authorize(scopedWrongOrgCtx, org.ID, organizations.RoleMember); err == nil {
		t.Error("Expected cross-org authorization error, got nil")
	}

	// 5. Suspended member must be rejected
	_, _ = orgs.UpdateMemberStatus(ctx, org.ID, "user_member", organizations.MembershipSuspended)
	if _, err := orgs.Authorize(memberCtx, org.ID, organizations.RoleMember); err == nil {
		t.Error("Suspended member authorized, expected error")
	}
}
