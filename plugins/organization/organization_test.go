package organization_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/BladiCreator/go-modular-auth/adapters/memory"
	"github.com/BladiCreator/go-modular-auth/auth"
	"github.com/BladiCreator/go-modular-auth/config"
	"github.com/BladiCreator/go-modular-auth/domain/dto"
	"github.com/BladiCreator/go-modular-auth/plugin"
	"github.com/BladiCreator/go-modular-auth/plugins"
	"github.com/BladiCreator/go-modular-auth/plugins/organization"
	"github.com/asaskevich/EventBus"
)

func setupTestEnvironment(opts ...organization.Option) (*organization.Plugin, *memory.Store, *plugin.Context) {
	store := memory.New()
	bus := EventBus.New()
	pCtx := plugin.NewContext(nil, bus)

	p := organization.New(store, opts...)
	_ = p.Init(pCtx)

	return p, store, pCtx
}

// 1. Organization Lifecycle Tests
func TestOrganization_Lifecycle(t *testing.T) {
	p, store, pCtx := setupTestEnvironment()
	ctx := context.Background()

	// Create User in store
	user, err := store.CreateUser(ctx, &dto.CreateUserParams{
		Name:  "Alice",
		Email: "alice@example.com",
	})
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	// 1. Create Organization
	createRes, err := p.CreateOrganization(ctx, organization.CreateOrganizationParams{
		UserID: user.ID,
		Name:   "Acme Corp",
		Slug:   "acme",
		Logo:   "https://example.com/logo.png",
		Metadata: map[string]any{
			"plan": "enterprise",
		},
	})
	if err != nil {
		t.Fatalf("CreateOrganization failed: %v", err)
	}

	if createRes.Organization.ID == "" {
		t.Fatal("expected non-empty organization ID")
	}
	if createRes.Organization.Slug != "acme" {
		t.Fatalf("expected slug 'acme', got %s", createRes.Organization.Slug)
	}
	if createRes.Member == nil || createRes.Member.Role != organization.RoleOwner {
		t.Fatalf("expected creator to be owner, got %+v", createRes.Member)
	}

	// Verify Active Org in context
	activeOrg, ok := pCtx.Get(organization.ActiveOrgContextKey(user.ID))
	if !ok || activeOrg != createRes.Organization.ID {
		t.Fatalf("expected active org in context to be %s, got %v", createRes.Organization.ID, activeOrg)
	}

	// 2. Duplicate Slug check
	_, err = p.CreateOrganization(ctx, organization.CreateOrganizationParams{
		UserID: user.ID,
		Name:   "Acme Duplicate",
		Slug:   "acme",
	})
	if err != organization.ErrSlugAlreadyExists {
		t.Fatalf("expected ErrSlugAlreadyExists, got %v", err)
	}

	// 3. CheckSlug
	slugRes, err := p.CheckSlug(ctx, organization.CheckSlugParams{Slug: "acme"})
	if err != nil || slugRes.Available {
		t.Fatalf("expected slug 'acme' to not be available, got available: %v, err: %v", slugRes.Available, err)
	}
	slugRes2, err := p.CheckSlug(ctx, organization.CheckSlugParams{Slug: "brand-new-slug"})
	if err != nil || !slugRes2.Available {
		t.Fatalf("expected 'brand-new-slug' to be available, got available: %v, err: %v", slugRes2.Available, err)
	}

	// 4. GetOrganization & GetOrganizationBySlug
	getRes, err := p.GetOrganization(ctx, organization.GetOrganizationParams{
		OrganizationID: createRes.Organization.ID,
	})
	if err != nil || getRes.Organization.Name != "Acme Corp" {
		t.Fatalf("GetOrganization failed: %v", err)
	}

	getBySlugRes, err := p.GetOrganizationBySlug(ctx, organization.GetOrganizationBySlugParams{
		Slug: "acme",
	})
	if err != nil || getBySlugRes.Organization.ID != createRes.Organization.ID {
		t.Fatalf("GetOrganizationBySlug failed: %v", err)
	}

	// 5. UpdateOrganization
	newName := "Acme Corporation"
	newSlug := "acme-corp"
	updateRes, err := p.UpdateOrganization(ctx, organization.UpdateOrganizationParams{
		OrganizationID: createRes.Organization.ID,
		UserID:         user.ID,
		Name:           &newName,
		Slug:           &newSlug,
	})
	if err != nil {
		t.Fatalf("UpdateOrganization failed: %v", err)
	}
	if updateRes.Organization.Name != "Acme Corporation" || updateRes.Organization.Slug != "acme-corp" {
		t.Fatalf("unexpected updated org: %+v", updateRes.Organization)
	}

	// 6. GetFullOrganization
	fullRes, err := p.GetFullOrganization(ctx, organization.GetFullOrganizationParams{
		OrganizationID: createRes.Organization.ID,
	})
	if err != nil {
		t.Fatalf("GetFullOrganization failed: %v", err)
	}
	if len(fullRes.Members) != 1 {
		t.Fatalf("expected 1 member in full org, got %d", len(fullRes.Members))
	}

	// 7. DeleteOrganization
	delRes, err := p.DeleteOrganization(ctx, organization.DeleteOrganizationParams{
		OrganizationID: createRes.Organization.ID,
		UserID:         user.ID,
	})
	if err != nil || !delRes.Success {
		t.Fatalf("DeleteOrganization failed: %v", err)
	}

	_, err = p.GetOrganization(ctx, organization.GetOrganizationParams{
		OrganizationID: createRes.Organization.ID,
	})
	if err != organization.ErrOrganizationNotFound {
		t.Fatalf("expected ErrOrganizationNotFound after delete, got %v", err)
	}
}

// 2. Member Lifecycle & Safety Tests
func TestOrganization_MemberLifecycleAndSafety(t *testing.T) {
	p, store, _ := setupTestEnvironment()
	ctx := context.Background()

	alice, _ := store.CreateUser(ctx, &dto.CreateUserParams{Name: "Alice", Email: "alice@example.com"})
	bob, _ := store.CreateUser(ctx, &dto.CreateUserParams{Name: "Bob", Email: "bob@example.com"})
	charlie, _ := store.CreateUser(ctx, &dto.CreateUserParams{Name: "Charlie", Email: "charlie@example.com"})

	// Create Org with Alice as Owner
	orgRes, err := p.CreateOrganization(ctx, organization.CreateOrganizationParams{
		UserID: alice.ID,
		Name:   "TechLab",
	})
	if err != nil {
		t.Fatalf("failed to create org: %v", err)
	}
	orgID := orgRes.Organization.ID

	// 1. Add Bob as Member
	addBobRes, err := p.AddMember(ctx, organization.AddMemberParams{
		OrganizationID: orgID,
		UserID:         bob.ID,
		Role:           organization.RoleMember,
		InvokingUserID: alice.ID,
	})
	if err != nil {
		t.Fatalf("AddMember bob failed: %v", err)
	}
	if addBobRes.Member.Role != organization.RoleMember {
		t.Fatalf("expected member role, got %s", addBobRes.Member.Role)
	}

	// 2. Prevent duplicate member
	_, err = p.AddMember(ctx, organization.AddMemberParams{
		OrganizationID: orgID,
		UserID:         bob.ID,
		Role:           organization.RoleMember,
	})
	if err != organization.ErrMemberAlreadyExists {
		t.Fatalf("expected ErrMemberAlreadyExists, got %v", err)
	}

	// 3. Add Charlie as Admin
	_, err = p.AddMember(ctx, organization.AddMemberParams{
		OrganizationID: orgID,
		UserID:         charlie.ID,
		Role:           organization.RoleAdmin,
		InvokingUserID: alice.ID,
	})
	if err != nil {
		t.Fatalf("AddMember charlie failed: %v", err)
	}

	// 4. Test Last Owner Safety - Demotion
	_, err = p.UpdateMemberRole(ctx, organization.UpdateMemberRoleParams{
		OrganizationID: orgID,
		UserID:         alice.ID,
		Role:           organization.RoleMember,
		InvokingUserID: alice.ID,
	})
	if err != organization.ErrCannotRemoveLastOwner {
		t.Fatalf("expected ErrCannotRemoveLastOwner when demoting only owner, got %v", err)
	}

	// 5. Test Last Owner Safety - Removal
	_, err = p.RemoveMember(ctx, organization.RemoveMemberParams{
		OrganizationID: orgID,
		UserID:         alice.ID,
		InvokingUserID: alice.ID,
	})
	if err != organization.ErrCannotRemoveLastOwner {
		t.Fatalf("expected ErrCannotRemoveLastOwner when removing only owner, got %v", err)
	}

	// 6. Test Last Owner Safety - Leaving
	_, err = p.LeaveOrganization(ctx, organization.LeaveOrganizationParams{
		OrganizationID: orgID,
		UserID:         alice.ID,
	})
	if err != organization.ErrCannotLeaveAsLastOwner {
		t.Fatalf("expected ErrCannotLeaveAsLastOwner when leaving as only owner, got %v", err)
	}

	// 7. Promote Bob to Owner, then Alice can step down
	_, err = p.UpdateMemberRole(ctx, organization.UpdateMemberRoleParams{
		OrganizationID: orgID,
		UserID:         bob.ID,
		Role:           organization.RoleOwner,
		InvokingUserID: alice.ID,
	})
	if err != nil {
		t.Fatalf("promoting Bob to owner failed: %v", err)
	}

	// Now Alice can safely leave
	leaveRes, err := p.LeaveOrganization(ctx, organization.LeaveOrganizationParams{
		OrganizationID: orgID,
		UserID:         alice.ID,
	})
	if err != nil || !leaveRes.Success {
		t.Fatalf("Alice leaving after second owner added failed: %v", err)
	}

	// 8. Test Member Pagination
	listRes, err := p.ListMembers(ctx, organization.ListMembersParams{
		OrganizationID: orgID,
		Limit:          1,
		Offset:         0,
	})
	if err != nil {
		t.Fatalf("ListMembers failed: %v", err)
	}
	if len(listRes.Members) != 1 || listRes.Total != 2 {
		t.Fatalf("expected 1 member in page and total 2, got len=%d total=%d", len(listRes.Members), listRes.Total)
	}
}

// 3. Invitation Lifecycle Tests
func TestOrganization_InvitationLifecycle(t *testing.T) {
	var emailDispatched bool
	var dispatchedEmail string

	p, store, _ := setupTestEnvironment(
		organization.WithInvitationExpiresIn(24*time.Hour),
		organization.WithSendInvitationEmail(func(ctx context.Context, data organization.InvitationEmailData) error {
			emailDispatched = true
			dispatchedEmail = data.Invitation.Email
			return nil
		}),
		organization.WithCancelPendingInvitationsOnReInvite(true),
	)
	ctx := context.Background()

	owner, _ := store.CreateUser(ctx, &dto.CreateUserParams{Name: "Owner", Email: "owner@example.com"})
	orgRes, _ := p.CreateOrganization(ctx, organization.CreateOrganizationParams{
		UserID: owner.ID,
		Name:   "Startup Inc",
	})
	orgID := orgRes.Organization.ID

	// 1. Create Invitation
	inviteRes, err := p.CreateInvitation(ctx, organization.CreateInvitationParams{
		OrganizationID: orgID,
		InviterID:      owner.ID,
		Email:          "invitee@example.com",
		Role:           organization.RoleAdmin,
	})
	if err != nil {
		t.Fatalf("CreateInvitation failed: %v", err)
	}
	if !emailDispatched || dispatchedEmail != "invitee@example.com" {
		t.Fatalf("expected invitation email to be dispatched, got %v / %s", emailDispatched, dispatchedEmail)
	}
	invitationID := inviteRes.Invitation.ID

	// 2. Re-inviting with CancelPendingInvitationsOnReInvite enabled
	reInviteRes, err := p.CreateInvitation(ctx, organization.CreateInvitationParams{
		OrganizationID: orgID,
		InviterID:      owner.ID,
		Email:          "invitee@example.com",
		Role:           organization.RoleAdmin,
	})
	if err != nil {
		t.Fatalf("Re-invitation failed: %v", err)
	}
	if reInviteRes.Invitation.ID == invitationID {
		t.Fatal("expected new invitation ID on re-invite")
	}

	// Verify old invitation is canceled
	oldInv, _ := p.GetInvitation(ctx, organization.GetInvitationParams{InvitationID: invitationID})
	if oldInv.Invitation.Status != organization.InvitationStatusCanceled {
		t.Fatalf("expected old invitation to be canceled, got %s", oldInv.Invitation.Status)
	}

	// 3. Accept Invitation
	newInvUserID := "user_invitee_123"
	acceptRes, err := p.AcceptInvitation(ctx, organization.AcceptInvitationParams{
		InvitationID: reInviteRes.Invitation.ID,
		UserID:       newInvUserID,
	})
	if err != nil {
		t.Fatalf("AcceptInvitation failed: %v", err)
	}
	if acceptRes.Member.Role != organization.RoleAdmin || acceptRes.Member.UserID != newInvUserID {
		t.Fatalf("unexpected member after acceptance: %+v", acceptRes.Member)
	}

	// 4. Reject & Cancel invitations
	inv3, _ := p.CreateInvitation(ctx, organization.CreateInvitationParams{
		OrganizationID: orgID,
		InviterID:      owner.ID,
		Email:          "reject_me@example.com",
	})
	rejectRes, err := p.RejectInvitation(ctx, organization.RejectInvitationParams{
		InvitationID: inv3.Invitation.ID,
	})
	if err != nil || rejectRes.Invitation.Status != organization.InvitationStatusRejected {
		t.Fatalf("RejectInvitation failed: %v", err)
	}

	inv4, _ := p.CreateInvitation(ctx, organization.CreateInvitationParams{
		OrganizationID: orgID,
		InviterID:      owner.ID,
		Email:          "cancel_me@example.com",
	})
	cancelRes, err := p.CancelInvitation(ctx, organization.CancelInvitationParams{
		InvitationID: inv4.Invitation.ID,
		UserID:       owner.ID,
	})
	if err != nil || cancelRes.Invitation.Status != organization.InvitationStatusCanceled {
		t.Fatalf("CancelInvitation failed: %v", err)
	}
}

// 4. Teams Sub-Module Tests
func TestOrganization_TeamsSubModule(t *testing.T) {
	// 1. When Teams is disabled
	pDisabled, storeDisabled, _ := setupTestEnvironment()
	ctx := context.Background()

	u, _ := storeDisabled.CreateUser(ctx, &dto.CreateUserParams{Name: "User", Email: "user@example.com"})
	org1, _ := pDisabled.CreateOrganization(ctx, organization.CreateOrganizationParams{UserID: u.ID, Name: "Org1"})

	_, err := pDisabled.CreateTeam(ctx, organization.CreateTeamParams{
		OrganizationID: org1.Organization.ID,
		Name:           "Dev Team",
	})
	if err != organization.ErrTeamsNotEnabled {
		t.Fatalf("expected ErrTeamsNotEnabled, got %v", err)
	}

	// 2. When Teams is enabled with defaultTeam
	p, store, _ := setupTestEnvironment(
		organization.WithTeams(true, true, false), // Teams enabled, DefaultTeam enabled, AllowRemovingAll = false
	)

	owner, _ := store.CreateUser(ctx, &dto.CreateUserParams{Name: "Alice", Email: "alice@example.com"})
	bob, _ := store.CreateUser(ctx, &dto.CreateUserParams{Name: "Bob", Email: "bob@example.com"})

	orgRes, err := p.CreateOrganization(ctx, organization.CreateOrganizationParams{
		UserID: owner.ID,
		Name:   "Enterprise Org",
	})
	if err != nil {
		t.Fatalf("CreateOrganization with teams failed: %v", err)
	}
	orgID := orgRes.Organization.ID

	// Check default team was created
	teamsRes, err := p.ListTeams(ctx, organization.ListTeamsParams{OrganizationID: orgID})
	if err != nil || len(teamsRes.Teams) != 1 {
		t.Fatalf("expected 1 default team, got %d (err: %v)", len(teamsRes.Teams), err)
	}
	defaultTeam := teamsRes.Teams[0]
	if defaultTeam.Name != "General" {
		t.Fatalf("expected default team name 'General', got %s", defaultTeam.Name)
	}

	// 3. Create Custom Team
	engTeamRes, err := p.CreateTeam(ctx, organization.CreateTeamParams{
		OrganizationID: orgID,
		UserID:         owner.ID,
		Name:           "Engineering",
	})
	if err != nil {
		t.Fatalf("CreateTeam failed: %v", err)
	}

	// Add Bob as org member then team member
	_, _ = p.AddMember(ctx, organization.AddMemberParams{
		OrganizationID: orgID,
		UserID:         bob.ID,
		Role:           organization.RoleMember,
		InvokingUserID: owner.ID,
	})

	addTMRes, err := p.AddTeamMember(ctx, organization.AddTeamMemberParams{
		TeamID:         engTeamRes.Team.ID,
		UserID:         bob.ID,
		InvokingUserID: owner.ID,
	})
	if err != nil || addTMRes.TeamMember.UserID != bob.ID {
		t.Fatalf("AddTeamMember failed: %v", err)
	}

	// 4. Active Team context
	activeTeamRes, err := p.SetActiveTeam(ctx, organization.SetActiveTeamParams{
		UserID: bob.ID,
		TeamID: engTeamRes.Team.ID,
	})
	if err != nil || activeTeamRes.Team.ID != engTeamRes.Team.ID {
		t.Fatalf("SetActiveTeam failed: %v", err)
	}

	getActTeam, err := p.GetActiveTeam(ctx, organization.GetActiveTeamParams{UserID: bob.ID})
	if err != nil || getActTeam.Team.ID != engTeamRes.Team.ID {
		t.Fatalf("GetActiveTeam failed: %v", err)
	}

	// 5. Deleting team protection when allowRemovingAll is false
	_, err = p.DeleteTeam(ctx, organization.DeleteTeamParams{TeamID: engTeamRes.Team.ID, UserID: owner.ID})
	if err != nil {
		t.Fatalf("Deleting engineering team failed: %v", err)
	}

	// Now only default team is left, attempting to delete should fail with ErrCannotRemoveAllTeams
	_, err = p.DeleteTeam(ctx, organization.DeleteTeamParams{TeamID: defaultTeam.ID, UserID: owner.ID})
	if err != organization.ErrCannotRemoveAllTeams {
		t.Fatalf("expected ErrCannotRemoveAllTeams, got %v", err)
	}
}

// 5. Access Control (Static & Dynamic RBAC) Tests
func TestOrganization_AccessControl_StaticAndDynamic(t *testing.T) {
	customRoles := map[string]organization.Permissions{
		"finance": {
			"billing": {"view", "pay"},
		},
		"support": {
			organization.ResourceMember: {organization.ActionRead},
		},
	}

	p, store, _ := setupTestEnvironment(
		organization.WithDynamicAccessControl(true),
		organization.WithCustomRoles(customRoles),
	)
	ctx := context.Background()

	owner, _ := store.CreateUser(ctx, &dto.CreateUserParams{Name: "Owner", Email: "owner@example.com"})
	orgRes, _ := p.CreateOrganization(ctx, organization.CreateOrganizationParams{
		UserID: owner.ID,
		Name:   "FinTech Ltd",
	})
	orgID := orgRes.Organization.ID

	// 1. Test Static Default Roles
	allowed, err := p.CheckPermission(ctx, orgID, organization.RoleOwner, organization.Permissions{
		organization.ResourceOrganization: {organization.ActionDelete},
	})
	if err != nil || !allowed {
		t.Fatalf("expected owner to have delete permission, got %v", allowed)
	}

	allowedAdmin, err := p.CheckPermission(ctx, orgID, organization.RoleAdmin, organization.Permissions{
		organization.ResourceOrganization: {organization.ActionDelete},
	})
	if err != nil || allowedAdmin {
		t.Fatalf("expected admin to NOT have delete organization permission, got %v", allowedAdmin)
	}

	// 2. Test Custom Static Role
	allowedFinance, err := p.CheckPermission(ctx, orgID, "finance", organization.Permissions{
		"billing": {"pay"},
	})
	if err != nil || !allowedFinance {
		t.Fatalf("expected finance role to have billing:pay, got %v", allowedFinance)
	}

	// 3. Test Dynamic Access Control - Create Role in DB
	createRoleRes, err := p.CreateRole(ctx, organization.CreateRoleParams{
		OrganizationID: orgID,
		UserID:         owner.ID,
		Role:           "moderator",
		Permissions: map[string][]string{
			"posts": {"moderate", "delete"},
		},
	})
	if err != nil {
		t.Fatalf("CreateRole failed: %v", err)
	}
	if createRoleRes.Role.Role != "moderator" {
		t.Fatalf("expected role moderator, got %s", createRoleRes.Role.Role)
	}

	// Test HasPermission with dynamic role
	hasPermRes, err := p.HasPermission(ctx, organization.HasPermissionParams{
		OrganizationID: orgID,
		Role:           "moderator",
		Permissions: organization.Permissions{
			"posts": {"moderate"},
		},
	})
	if err != nil || !hasPermRes.HasPermission {
		t.Fatalf("expected dynamic role moderator to have posts:moderate, got %v", hasPermRes.HasPermission)
	}

	// 4. Test Compound Roles (e.g. "finance,moderator")
	compoundPerm, err := p.CheckPermission(ctx, orgID, "finance,moderator", organization.Permissions{
		"billing": {"pay"},
		"posts":   {"moderate"},
	})
	if err != nil || !compoundPerm {
		t.Fatalf("expected compound role 'finance,moderator' to satisfy combined permissions, got %v", compoundPerm)
	}
}

// 6. Config Limits Tests
func TestOrganization_ConfigLimits(t *testing.T) {
	p, store, _ := setupTestEnvironment(
		organization.WithOrganizationLimit(2),
		organization.WithMembershipLimit(2),
		organization.WithInvitationLimit(1),
	)
	ctx := context.Background()

	u, _ := store.CreateUser(ctx, &dto.CreateUserParams{Name: "User", Email: "user@example.com"})

	// 1. Org creation limit
	_, err := p.CreateOrganization(ctx, organization.CreateOrganizationParams{UserID: u.ID, Name: "Org 1"})
	if err != nil {
		t.Fatalf("Org 1 create failed: %v", err)
	}
	org2, err := p.CreateOrganization(ctx, organization.CreateOrganizationParams{UserID: u.ID, Name: "Org 2"})
	if err != nil {
		t.Fatalf("Org 2 create failed: %v", err)
	}
	_, err = p.CreateOrganization(ctx, organization.CreateOrganizationParams{UserID: u.ID, Name: "Org 3"})
	if err != organization.ErrOrganizationLimitReached {
		t.Fatalf("expected ErrOrganizationLimitReached, got %v", err)
	}

	// 2. Membership limit (Org 2 has 1 owner, limit is 2)
	u2, _ := store.CreateUser(ctx, &dto.CreateUserParams{Name: "User2", Email: "user2@example.com"})
	u3, _ := store.CreateUser(ctx, &dto.CreateUserParams{Name: "User3", Email: "user3@example.com"})

	_, err = p.AddMember(ctx, organization.AddMemberParams{
		OrganizationID: org2.Organization.ID,
		UserID:         u2.ID,
		Role:           organization.RoleMember,
	})
	if err != nil {
		t.Fatalf("Add member 2 failed: %v", err)
	}

	_, err = p.AddMember(ctx, organization.AddMemberParams{
		OrganizationID: org2.Organization.ID,
		UserID:         u3.ID,
		Role:           organization.RoleMember,
	})
	if err != organization.ErrMembershipLimitReached {
		t.Fatalf("expected ErrMembershipLimitReached, got %v", err)
	}

	// 3. Invitation limit
	_, err = p.CreateInvitation(ctx, organization.CreateInvitationParams{
		OrganizationID: org2.Organization.ID,
		InviterID:      u.ID,
		Email:          "invite1@example.com",
	})
	if err != nil {
		t.Fatalf("CreateInvitation 1 failed: %v", err)
	}

	_, err = p.CreateInvitation(ctx, organization.CreateInvitationParams{
		OrganizationID: org2.Organization.ID,
		InviterID:      u.ID,
		Email:          "invite2@example.com",
	})
	if err != organization.ErrInvitationLimitReached {
		t.Fatalf("expected ErrInvitationLimitReached, got %v", err)
	}
}

// 7. Event Emissions & Extra Metadata
func TestOrganization_EventEmissionsAndExtra(t *testing.T) {
	p, store, pCtx := setupTestEnvironment()
	ctx := context.Background()

	var eventOrgCreatedAfter bool
	pCtx.Events().Subscribe(organization.EventOrgCreateAfter, func(payload *organization.OrgCreateAfterEventPayload) {
		eventOrgCreatedAfter = true
		if payload.Extra["source"] != "mobile_app" {
			t.Errorf("expected Extra[source] = mobile_app, got %v", payload.Extra["source"])
		}
	})

	u, _ := store.CreateUser(ctx, &dto.CreateUserParams{Name: "Sam", Email: "sam@example.com"})

	params := organization.CreateOrganizationParams{
		UserID: u.ID,
		Name:   "App Studio",
	}
	params.Set("source", "mobile_app")

	res, err := p.CreateOrganization(ctx, params)
	if err != nil {
		t.Fatalf("CreateOrganization failed: %v", err)
	}

	if !eventOrgCreatedAfter {
		t.Fatal("expected EventOrgCreateAfter to be published")
	}

	val, ok := params.Get("source")
	if !ok || val != "mobile_app" {
		t.Fatalf("expected params.Get(source) = mobile_app, got %v", val)
	}
	_ = res
}

// 8. Auth Engine Integration Test
func TestOrganization_AuthEngineIntegration(t *testing.T) {
	store := memory.New()
	orgPlugin := plugins.Organization(store, organization.WithTeams(true, true, true))

	authEngine, err := auth.New(
		config.WithPlugins(orgPlugin),
	)
	if err != nil {
		t.Fatalf("auth.New failed: %v", err)
	}

	resolvedPlugin := auth.Plugin[organization.Plugin](authEngine)
	if resolvedPlugin == nil || resolvedPlugin.ID() != organization.PluginID {
		t.Fatalf("failed to resolve Organization plugin from auth engine")
	}
}

// 9. Concurrency & Race Detector Tests
func TestOrganization_Concurrency(t *testing.T) {
	p, store, _ := setupTestEnvironment()
	ctx := context.Background()

	owner, _ := store.CreateUser(ctx, &dto.CreateUserParams{Name: "Owner", Email: "owner@example.com"})
	orgRes, _ := p.CreateOrganization(ctx, organization.CreateOrganizationParams{
		UserID: owner.ID,
		Name:   "Concurrent Org",
	})
	orgID := orgRes.Organization.ID

	var wg sync.WaitGroup
	const workerCount = 20

	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			user, _ := store.CreateUser(ctx, &dto.CreateUserParams{
				Name:  "Worker",
				Email: "worker" + string(rune(idx+'a')) + "@example.com",
			})
			if user != nil {
				_, _ = p.AddMember(ctx, organization.AddMemberParams{
					OrganizationID: orgID,
					UserID:         user.ID,
					Role:           organization.RoleMember,
				})
			}
			_, _ = p.GetOrganization(ctx, organization.GetOrganizationParams{OrganizationID: orgID})
			_, _ = p.ListMembers(ctx, organization.ListMembersParams{OrganizationID: orgID, Limit: 10})
		}(i)
	}

	wg.Wait()
}

// 10. Dynamic Role CRUD Tests
func TestOrganization_DynamicRoleCRUD(t *testing.T) {
	p, store, _ := setupTestEnvironment(
		organization.WithDynamicAccessControl(true),
		organization.WithDynamicAccessControlLimits(func(ctx context.Context, orgID string) (int, error) {
			return 2, nil
		}),
	)
	ctx := context.Background()

	owner, _ := store.CreateUser(ctx, &dto.CreateUserParams{Name: "Owner", Email: "owner@example.com"})
	orgRes, _ := p.CreateOrganization(ctx, organization.CreateOrganizationParams{UserID: owner.ID, Name: "Dynamic Corp"})
	orgID := orgRes.Organization.ID

	// 1. Create Role
	role1, err := p.CreateRole(ctx, organization.CreateRoleParams{
		OrganizationID: orgID,
		UserID:         owner.ID,
		Role:           "editor",
		Permissions: map[string][]string{
			"articles": {"create", "edit"},
		},
	})
	if err != nil {
		t.Fatalf("CreateRole editor failed: %v", err)
	}

	// 2. Duplicate Role check
	_, err = p.CreateRole(ctx, organization.CreateRoleParams{
		OrganizationID: orgID,
		UserID:         owner.ID,
		Role:           "editor",
		Permissions:    map[string][]string{"articles": {"create"}},
	})
	if err != organization.ErrRoleAlreadyExists {
		t.Fatalf("expected ErrRoleAlreadyExists, got %v", err)
	}

	// 3. Get Role
	getRole, err := p.GetRole(ctx, organization.GetRoleParams{RoleID: role1.Role.ID})
	if err != nil || getRole.Role.Role != "editor" {
		t.Fatalf("GetRole failed: %v", err)
	}

	// 4. Update Role
	newRoleName := "chief-editor"
	updateRole, err := p.UpdateRole(ctx, organization.UpdateRoleParams{
		RoleID: role1.Role.ID,
		UserID: owner.ID,
		Role:   &newRoleName,
	})
	if err != nil || updateRole.Role.Role != "chief-editor" {
		t.Fatalf("UpdateRole failed: %v", err)
	}

	// 5. Dynamic Role Limit check (limit is 2)
	_, err = p.CreateRole(ctx, organization.CreateRoleParams{
		OrganizationID: orgID,
		UserID:         owner.ID,
		Role:           "viewer",
		Permissions:    map[string][]string{"articles": {"read"}},
	})
	if err != nil {
		t.Fatalf("CreateRole viewer failed: %v", err)
	}

	_, err = p.CreateRole(ctx, organization.CreateRoleParams{
		OrganizationID: orgID,
		UserID:         owner.ID,
		Role:           "reviewer",
		Permissions:    map[string][]string{"articles": {"review"}},
	})
	if err != organization.ErrRolesLimitReached {
		t.Fatalf("expected ErrRolesLimitReached, got %v", err)
	}

	// 6. List Roles
	listRoles, err := p.ListRoles(ctx, organization.ListRolesParams{OrganizationID: orgID})
	if err != nil || len(listRoles.Roles) != 2 {
		t.Fatalf("expected 2 roles, got %d (err: %v)", len(listRoles.Roles), err)
	}

	// 7. Delete Role
	delRole, err := p.DeleteRole(ctx, organization.DeleteRoleParams{RoleID: role1.Role.ID, UserID: owner.ID})
	if err != nil || !delRole.Success {
		t.Fatalf("DeleteRole failed: %v", err)
	}
}

// 11. Expired Invitation Test
func TestOrganization_ExpiredInvitation(t *testing.T) {
	p, store, _ := setupTestEnvironment(
		organization.WithInvitationExpiresIn(1 * time.Millisecond),
	)
	ctx := context.Background()

	owner, _ := store.CreateUser(ctx, &dto.CreateUserParams{Name: "Owner", Email: "owner@example.com"})
	invitee, _ := store.CreateUser(ctx, &dto.CreateUserParams{Name: "Invitee", Email: "invitee@example.com"})
	orgRes, _ := p.CreateOrganization(ctx, organization.CreateOrganizationParams{UserID: owner.ID, Name: "Expiring Org"})

	inv, err := p.CreateInvitation(ctx, organization.CreateInvitationParams{
		OrganizationID: orgRes.Organization.ID,
		InviterID:      owner.ID,
		Email:          invitee.Email,
	})
	if err != nil {
		t.Fatalf("CreateInvitation failed: %v", err)
	}

	// Sleep slightly to ensure expiration
	time.Sleep(5 * time.Millisecond)

	_, err = p.AcceptInvitation(ctx, organization.AcceptInvitationParams{
		InvitationID: inv.Invitation.ID,
		UserID:       invitee.ID,
	})
	if err != organization.ErrInvitationExpired {
		t.Fatalf("expected ErrInvitationExpired, got %v", err)
	}
}

// 12. Active Context & Fallback Tests
func TestOrganization_ActiveContextFallback(t *testing.T) {
	p, store, _ := setupTestEnvironment()
	ctx := context.Background()

	u, _ := store.CreateUser(ctx, &dto.CreateUserParams{Name: "MultiUser", Email: "multi@example.com"})

	// User creates Org
	orgRes, err := p.CreateOrganization(ctx, organization.CreateOrganizationParams{
		UserID: u.ID,
		Name:   "Primary Org",
	})
	if err != nil {
		t.Fatalf("CreateOrganization failed: %v", err)
	}

	// Fetch active organization without explicitly setting context
	actOrg, err := p.GetActiveOrganization(ctx, organization.GetActiveOrganizationParams{UserID: u.ID})
	if err != nil || actOrg.Organization.ID != orgRes.Organization.ID {
		t.Fatalf("GetActiveOrganization fallback failed: %v", err)
	}

	// Fetch active member and role
	actMember, err := p.GetActiveMember(ctx, organization.GetActiveMemberParams{UserID: u.ID})
	if err != nil || actMember.Member.Role != organization.RoleOwner {
		t.Fatalf("GetActiveMember failed: %v", err)
	}

	actRole, err := p.GetActiveMemberRole(ctx, organization.GetActiveMemberRoleParams{UserID: u.ID})
	if err != nil || actRole.Role != organization.RoleOwner {
		t.Fatalf("GetActiveMemberRole failed: %v", err)
	}
}

// 13. AllowOrgCreation Callback Test
func TestOrganization_AllowOrgCreationCallback(t *testing.T) {
	p, store, _ := setupTestEnvironment(
		organization.WithAllowUserToCreateOrganization(func(ctx context.Context, userID string) (bool, error) {
			return userID == "admin_user", nil
		}),
	)
	ctx := context.Background()

	user1, _ := store.CreateUser(ctx, &dto.CreateUserParams{Name: "Regular", Email: "regular@example.com"})

	_, err := p.CreateOrganization(ctx, organization.CreateOrganizationParams{
		UserID: user1.ID,
		Name:   "Blocked Org",
	})
	if err != organization.ErrPermissionDenied {
		t.Fatalf("expected ErrPermissionDenied when creator not allowed, got %v", err)
	}

	_, err = p.CreateOrganization(ctx, organization.CreateOrganizationParams{
		UserID: "admin_user",
		Name:   "Allowed Org",
	})
	if err != nil {
		t.Fatalf("CreateOrganization for admin_user failed: %v", err)
	}
}

