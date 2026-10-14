# GoModularAuth Organizations Plugin

[![Go Reference](https://pkg.go.dev/badge/github.com/BladiCreator/go-modular-auth/plugins/organizations.svg)](https://pkg.go.dev/github.com/BladiCreator/go-modular-auth/plugins/organizations)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

`gomodularauth-organizations` provides multi-tenant organizations, memberships, role-based member permissions, teams, team memberships, invitations, organization metadata, ownership lifecycle, and organization-scoped authorization for GoModularAuth.

---

## Architecture & Design Principles

```text
┌────────────────────────────────────────────────────────┐
│                      Application                       │
└────────────────────────────────────────────────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────┐
│                   GoModularAuth Core                   │
│         (Auth, Principal, Events, Hooks, Clock)        │
└────────────────────────────────────────────────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────┐
│             gomodularauth-organizations                │
│   - Organization & Multi-Tenancy Boundary              │
│   - Memberships & Role Hierarchies                     │
│   - Teams & Department Rosters                         │
│   - Invitations (Single-use, Cryptographic Tokens)     │
│   - Scoped Principal Authorization                     │
│   - Cache-Aside Acceleration & Immediate Invalidation  │
└────────────────────────────────────────────────────────┘
        │                                  │
        ▼                                  ▼
┌───────────────────────┐        ┌───────────────────────┐
│     Store Adapter     │        │     Cache Adapter     │
│  (Memory / PostgreSQL)│        │   (Core Cache Engine) │
└───────────────────────┘        └───────────────────────┘
```

- **Core User Semantics Preserved**: Does not modify Core User semantics. References users strictly via Core `UserID` strings.
- **Store as Single Source of Truth**: All tenant, membership, team, and invitation state is persisted through explicit Store contracts.
- **Strict Tenant Isolation**: All queries and mutations are isolated by `OrganizationID`. Cross-organization authorization attempts are blocked with `ErrCrossOrganizationAccess`.
- **Organization-Scoped Principal Authorization**: Evaluates authenticated Core `Principal` identity and verifies active membership and role requirements.
- **Cryptographic Security**: Invitation tokens are generated via `crypto/rand`, SHA-256 hashed before storage, and compared in constant time (`crypto/subtle.ConstantTimeCompare`).
- **Single-Use Semantics**: Invitation redemption is atomic and protected against concurrency race conditions.

---

## Installation

```bash
go get github.com/BladiCreator/go-modular-auth/plugins/organizations
```

---

## Quick Start & Registration

```go
package main

import (
	"context"
	"database/sql"
	"log"

	auth "github.com/BladiCreator/go-modular-auth"
	memcache "github.com/BladiCreator/go-modular-auth/cache/memory"
	coremem "github.com/BladiCreator/go-modular-auth/store/memory"
	"github.com/BladiCreator/go-modular-auth/plugins/organizations"
	"github.com/BladiCreator/go-modular-auth/plugins/organizations/plugins"
	orgpostgres "github.com/BladiCreator/go-modular-auth/plugins/organizations/store/postgres"
)

func main() {
	ctx := context.Background()

	// 1. Database connection pool (e.g. PostgreSQL)
	db, err := sql.Open("postgres", "postgres://localhost:5432/myapp?sslmode=disable")
	if err != nil {
		log.Fatal(err)
	}

	// 2. Initialize GoModularAuth with Organizations plugin
	a, err := auth.New(auth.Config{
		Store: coremem.New(),
		Cache: memcache.New(),
		Plugins: []auth.PluginModule{
			organizations.New(
				organizations.WithStore(orgpostgres.New(db)),
			),
		},
	})
	if err != nil {
		log.Fatalf("failed to initialize auth: %v", err)
	}

	// 3. Resolve typed Capability via auth.Get[plugins.Organization]()
	orgs, err := auth.Get[plugins.Organization](a)
	if err != nil {
		log.Fatalf("failed to resolve capability: %v", err)
	}

	// 4. Create an Organization (atomically assigns owner as RoleOwner)
	org, err := orgs.CreateOrganization(ctx, organizations.CreateOrganizationInput{
		Name:    "Acme Corp",
		Slug:    "acme",
		OwnerID: "usr_alice",
		Metadata: map[string]string{
			"tier": "enterprise",
		},
	})
	if err != nil {
		log.Fatalf("failed to create organization: %v", err)
	}

	log.Printf("Created organization %s (%s)", org.Name, org.ID)
}
```

---

## Public API & Capability Contract

The plugin exposes the `Organization` interface (aliased as `Capability` and in `plugins.Organization`):

```go
type Organization interface {
	// Organization Lifecycle
	CreateOrganization(ctx context.Context, in CreateOrganizationInput) (*OrganizationRecord, error)
	GetOrganization(ctx context.Context, orgID string) (*OrganizationRecord, error)
	GetOrganizationBySlug(ctx context.Context, slug string) (*OrganizationRecord, error)
	UpdateOrganization(ctx context.Context, orgID string, in UpdateOrganizationInput) (*OrganizationRecord, error)
	DeleteOrganization(ctx context.Context, orgID string) error
	ListUserOrganizations(ctx context.Context, userID string) ([]*OrganizationRecord, error)
	TransferOwnership(ctx context.Context, orgID, newOwnerUserID string) error

	// Membership Management
	AddMember(ctx context.Context, in AddMemberInput) (*Membership, error)
	GetMember(ctx context.Context, orgID, userID string) (*Membership, error)
	UpdateMemberRole(ctx context.Context, orgID, userID string, role Role) (*Membership, error)
	UpdateMemberStatus(ctx context.Context, orgID, userID string, status MembershipStatus) (*Membership, error)
	RemoveMember(ctx context.Context, orgID, userID string) error
	ListMembers(ctx context.Context, orgID string) ([]*Membership, error)

	// Team Management
	CreateTeam(ctx context.Context, in CreateTeamInput) (*Team, error)
	GetTeam(ctx context.Context, orgID, teamID string) (*Team, error)
	UpdateTeam(ctx context.Context, orgID, teamID string, in UpdateTeamInput) (*Team, error)
	DeleteTeam(ctx context.Context, orgID, teamID string) error
	ListTeams(ctx context.Context, orgID string) ([]*Team, error)
	AddTeamMember(ctx context.Context, orgID, teamID, userID string) error
	RemoveTeamMember(ctx context.Context, orgID, teamID, userID string) error
	ListTeamMembers(ctx context.Context, orgID, teamID string) ([]string, error)

	// Invitations
	CreateInvitation(ctx context.Context, in CreateInvitationInput) (*Invitation, string, error)
	GetInvitation(ctx context.Context, orgID, invitationID string) (*Invitation, error)
	ListInvitations(ctx context.Context, orgID string) ([]*Invitation, error)
	AcceptInvitation(ctx context.Context, rawToken, userID string) (*Membership, error)
	RevokeInvitation(ctx context.Context, orgID, invitationID string) error

	// Scoped Authorization
	Authorize(ctx context.Context, orgID string, minRole Role) (*Membership, error)
}
```

---

## Organization-Scoped Authorization

To authorize incoming requests within an organization tenant:

```go
func handleSensitiveAction(ctx context.Context, orgs organizations.Organization, orgID string) error {
	// Verifies that the principal in ctx has at least RoleAdmin in orgID
	membership, err := orgs.Authorize(ctx, orgID, organizations.RoleAdmin)
	if err != nil {
		return err // Returns ErrUnauthorized or ErrCrossOrganizationAccess
	}

	log.Printf("User %s authorized with role %s", membership.UserID, membership.Role)
	return nil
}
```

Context scoping helper:

```go
// Bind organization to HTTP/gRPC request context:
ctx = organizations.WithOrganizationContext(ctx, "org_123")
```

---

## Events

The plugin publishes domain events to GoModularAuth's event bus after successful store commits:

| Event Name | Payload | Description |
|---|---|---|
| `organizations.created` | `OrganizationCreatedPayload` | Emitted when an organization is created |
| `organizations.updated` | `OrganizationUpdatedPayload` | Emitted when name or metadata is updated |
| `organizations.deleted` | `OrganizationDeletedPayload` | Emitted when an organization is removed |
| `organizations.ownership_transferred` | `OwnershipTransferredPayload` | Emitted when ownership changes hands |
| `organizations.member_added` | `MemberAddedPayload` | Emitted when a new member joins |
| `organizations.member_updated` | `MemberUpdatedPayload` | Emitted when a member's role or status changes |
| `organizations.member_removed` | `MemberRemovedPayload` | Emitted when a member is removed |
| `organizations.team_created` | `TeamCreatedPayload` | Emitted when a team is created |
| `organizations.team_updated` | `TeamUpdatedPayload` | Emitted when a team is updated |
| `organizations.team_deleted` | `TeamDeletedPayload` | Emitted when a team is deleted |
| `organizations.team_member_added` | `TeamMemberPayload` | Emitted when a user is enrolled in a team |
| `organizations.team_member_removed` | `TeamMemberPayload` | Emitted when a user is disenrolled from a team |
| `organizations.invitation_created` | `InvitationCreatedPayload` | Emitted when an invitation is issued |
| `organizations.invitation_accepted` | `InvitationAcceptedPayload` | Emitted when an invitation is accepted |
| `organizations.invitation_revoked` | `InvitationRevokedPayload` | Emitted when an invitation is cancelled |

---

## Store & Migrations

PostgreSQL DDL migrations are located in `migrations/001_create_organizations_tables.sql`.

Tables created:
- `organizations`: Tenant boundaries and metadata.
- `organization_memberships`: User-to-organization relationships, roles, and status.
- `organization_teams`: Department and sub-team boundaries.
- `organization_team_members`: User enrollment in teams.
- `organization_invitations`: Pending invitations with secure token hashes.
