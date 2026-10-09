// Package memory provides an in-memory, thread-safe implementation of store.Store.
// Ideal for unit testing, integration tests, and local ephemeral execution.
package memory

import (
	"context"
	"maps"
	"slices"
	"sync"

	"github.com/BladiCreator/go-modular-auth-organizations/store"
)

type txKey struct{ s *Store }

type data struct {
	orgsByID   map[string]*store.Organization
	orgsBySlug map[string]string // slug -> ID

	memberships map[string]*store.Membership // key: orgID + ":" + userID

	teamsByID   map[string]*store.Team // key: orgID + ":" + teamID
	teamsBySlug map[string]string      // key: orgID + ":" + slug -> teamID
	teamMembers map[string][]string    // key: teamID -> []userID

	invitationsByID   map[string]*store.Invitation // key: orgID + ":" + invID
	invitationsByHash map[string]*store.Invitation // key: tokenHash -> inv
}

func newData() data {
	return data{
		orgsByID:          make(map[string]*store.Organization),
		orgsBySlug:        make(map[string]string),
		memberships:       make(map[string]*store.Membership),
		teamsByID:         make(map[string]*store.Team),
		teamsBySlug:       make(map[string]string),
		teamMembers:       make(map[string][]string),
		invitationsByID:   make(map[string]*store.Invitation),
		invitationsByHash: make(map[string]*store.Invitation),
	}
}

func (d data) clone() data {
	clonedTeamMembers := make(map[string][]string, len(d.teamMembers))
	for k, v := range d.teamMembers {
		clonedTeamMembers[k] = slices.Clone(v)
	}

	return data{
		orgsByID:          maps.Clone(d.orgsByID),
		orgsBySlug:        maps.Clone(d.orgsBySlug),
		memberships:       maps.Clone(d.memberships),
		teamsByID:         maps.Clone(d.teamsByID),
		teamsBySlug:       maps.Clone(d.teamsBySlug),
		teamMembers:       clonedTeamMembers,
		invitationsByID:   maps.Clone(d.invitationsByID),
		invitationsByHash: maps.Clone(d.invitationsByHash),
	}
}

// Store implements store.Store using in-memory maps guarded by a read-write mutex.
type Store struct {
	txMu sync.Mutex   // serializes transactions
	mu   sync.RWMutex // guards data
	data data
}

var _ store.Store = (*Store)(nil)

// New constructs a new initialized in-memory organizations Store.
func New() *Store {
	return &Store{
		data: newData(),
	}
}

func (s *Store) inTx(ctx context.Context) bool {
	v, _ := ctx.Value(txKey{s}).(bool)
	return v
}

// Transaction executes fn with atomic snapshot rollback.
func (s *Store) Transaction(ctx context.Context, fn func(ctx context.Context) error) error {
	if s.inTx(ctx) {
		return fn(ctx)
	}

	s.txMu.Lock()
	defer s.txMu.Unlock()

	s.mu.RLock()
	snapshot := s.data.clone()
	s.mu.RUnlock()

	txCtx := context.WithValue(ctx, txKey{s}, true)
	if err := fn(txCtx); err != nil {
		s.mu.Lock()
		s.data = snapshot
		s.mu.Unlock()
		return err
	}
	return nil
}

func (s *Store) read(ctx context.Context, fn func(d *data) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return fn(&s.data)
}

func (s *Store) write(ctx context.Context, fn func(d *data) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !s.inTx(ctx) {
		s.txMu.Lock()
		defer s.txMu.Unlock()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return fn(&s.data)
}

// CreateOrganization stores a new organization.
func (s *Store) CreateOrganization(ctx context.Context, org *store.Organization) error {
	return s.write(ctx, func(d *data) error {
		if _, exists := d.orgsByID[org.ID]; exists {
			return store.ErrConflict
		}
		if _, exists := d.orgsBySlug[org.Slug]; exists {
			return store.ErrConflict
		}

		clone := cloneOrg(org)
		d.orgsByID[org.ID] = clone
		d.orgsBySlug[org.Slug] = org.ID
		return nil
	})
}

// GetOrganizationByID retrieves an organization by ID.
func (s *Store) GetOrganizationByID(ctx context.Context, id string) (*store.Organization, error) {
	var result *store.Organization
	err := s.read(ctx, func(d *data) error {
		org, exists := d.orgsByID[id]
		if !exists {
			return store.ErrNotFound
		}
		result = cloneOrg(org)
		return nil
	})
	return result, err
}

// GetOrganizationBySlug retrieves an organization by slug.
func (s *Store) GetOrganizationBySlug(ctx context.Context, slug string) (*store.Organization, error) {
	var result *store.Organization
	err := s.read(ctx, func(d *data) error {
		id, exists := d.orgsBySlug[slug]
		if !exists {
			return store.ErrNotFound
		}
		result = cloneOrg(d.orgsByID[id])
		return nil
	})
	return result, err
}

// UpdateOrganization updates organization details.
func (s *Store) UpdateOrganization(ctx context.Context, org *store.Organization) error {
	return s.write(ctx, func(d *data) error {
		existing, exists := d.orgsByID[org.ID]
		if !exists {
			return store.ErrNotFound
		}

		if existing.Slug != org.Slug {
			if _, slugTaken := d.orgsBySlug[org.Slug]; slugTaken {
				return store.ErrConflict
			}
			delete(d.orgsBySlug, existing.Slug)
			d.orgsBySlug[org.Slug] = org.ID
		}

		d.orgsByID[org.ID] = cloneOrg(org)
		return nil
	})
}

// DeleteOrganization removes an organization and cascades to related elements.
func (s *Store) DeleteOrganization(ctx context.Context, id string) error {
	return s.write(ctx, func(d *data) error {
		org, exists := d.orgsByID[id]
		if !exists {
			return store.ErrNotFound
		}

		delete(d.orgsByID, id)
		delete(d.orgsBySlug, org.Slug)

		// Cascade memberships
		for k, m := range d.memberships {
			if m.OrganizationID == id {
				delete(d.memberships, k)
			}
		}

		// Cascade teams & team members
		for k, t := range d.teamsByID {
			if t.OrganizationID == id {
				delete(d.teamsByID, k)
				delete(d.teamsBySlug, id+":"+t.Slug)
				delete(d.teamMembers, t.ID)
			}
		}

		// Cascade invitations
		for k, inv := range d.invitationsByID {
			if inv.OrganizationID == id {
				delete(d.invitationsByID, k)
				delete(d.invitationsByHash, inv.TokenHash)
			}
		}

		return nil
	})
}

// ListOrganizationsByUser returns all organizations where user is an active member.
func (s *Store) ListOrganizationsByUser(ctx context.Context, userID string) ([]*store.Organization, error) {
	var result []*store.Organization
	err := s.read(ctx, func(d *data) error {
		for _, m := range d.memberships {
			if m.UserID == userID && m.Status == store.MembershipActive {
				if org, exists := d.orgsByID[m.OrganizationID]; exists {
					result = append(result, cloneOrg(org))
				}
			}
		}
		return nil
	})
	return result, err
}

// CreateMembership persists a new membership.
func (s *Store) CreateMembership(ctx context.Context, m *store.Membership) error {
	return s.write(ctx, func(d *data) error {
		key := m.OrganizationID + ":" + m.UserID
		if _, exists := d.memberships[key]; exists {
			return store.ErrConflict
		}

		d.memberships[key] = cloneMembership(m)
		return nil
	})
}

// GetMembership retrieves a member record.
func (s *Store) GetMembership(ctx context.Context, orgID, userID string) (*store.Membership, error) {
	var result *store.Membership
	err := s.read(ctx, func(d *data) error {
		key := orgID + ":" + userID
		m, exists := d.memberships[key]
		if !exists {
			return store.ErrNotFound
		}
		result = cloneMembership(m)
		return nil
	})
	return result, err
}

// UpdateMembership updates a membership.
func (s *Store) UpdateMembership(ctx context.Context, m *store.Membership) error {
	return s.write(ctx, func(d *data) error {
		key := m.OrganizationID + ":" + m.UserID
		if _, exists := d.memberships[key]; !exists {
			return store.ErrNotFound
		}

		d.memberships[key] = cloneMembership(m)
		return nil
	})
}

// DeleteMembership deletes a membership.
func (s *Store) DeleteMembership(ctx context.Context, orgID, userID string) error {
	return s.write(ctx, func(d *data) error {
		key := orgID + ":" + userID
		if _, exists := d.memberships[key]; !exists {
			return store.ErrNotFound
		}

		delete(d.memberships, key)
		return nil
	})
}

// ListMembershipsByOrg returns all memberships for an organization.
func (s *Store) ListMembershipsByOrg(ctx context.Context, orgID string) ([]*store.Membership, error) {
	var result []*store.Membership
	err := s.read(ctx, func(d *data) error {
		for _, m := range d.memberships {
			if m.OrganizationID == orgID {
				result = append(result, cloneMembership(m))
			}
		}
		return nil
	})
	return result, err
}

// CreateTeam persists a new team.
func (s *Store) CreateTeam(ctx context.Context, t *store.Team) error {
	return s.write(ctx, func(d *data) error {
		idKey := t.OrganizationID + ":" + t.ID
		slugKey := t.OrganizationID + ":" + t.Slug

		if _, exists := d.teamsByID[idKey]; exists {
			return store.ErrConflict
		}
		if _, exists := d.teamsBySlug[slugKey]; exists {
			return store.ErrConflict
		}

		clone := cloneTeam(t)
		d.teamsByID[idKey] = clone
		d.teamsBySlug[slugKey] = t.ID
		return nil
	})
}

// GetTeamByID retrieves a team by ID.
func (s *Store) GetTeamByID(ctx context.Context, orgID, teamID string) (*store.Team, error) {
	var result *store.Team
	err := s.read(ctx, func(d *data) error {
		key := orgID + ":" + teamID
		t, exists := d.teamsByID[key]
		if !exists {
			return store.ErrNotFound
		}
		result = cloneTeam(t)
		return nil
	})
	return result, err
}

// GetTeamBySlug retrieves a team by slug.
func (s *Store) GetTeamBySlug(ctx context.Context, orgID, slug string) (*store.Team, error) {
	var result *store.Team
	err := s.read(ctx, func(d *data) error {
		slugKey := orgID + ":" + slug
		teamID, exists := d.teamsBySlug[slugKey]
		if !exists {
			return store.ErrNotFound
		}
		result = cloneTeam(d.teamsByID[orgID+":"+teamID])
		return nil
	})
	return result, err
}

// UpdateTeam updates team details.
func (s *Store) UpdateTeam(ctx context.Context, t *store.Team) error {
	return s.write(ctx, func(d *data) error {
		idKey := t.OrganizationID + ":" + t.ID
		existing, exists := d.teamsByID[idKey]
		if !exists {
			return store.ErrNotFound
		}

		if existing.Slug != t.Slug {
			newSlugKey := t.OrganizationID + ":" + t.Slug
			if _, slugTaken := d.teamsBySlug[newSlugKey]; slugTaken {
				return store.ErrConflict
			}
			delete(d.teamsBySlug, t.OrganizationID+":"+existing.Slug)
			d.teamsBySlug[newSlugKey] = t.ID
		}

		d.teamsByID[idKey] = cloneTeam(t)
		return nil
	})
}

// DeleteTeam removes a team and its memberships.
func (s *Store) DeleteTeam(ctx context.Context, orgID, teamID string) error {
	return s.write(ctx, func(d *data) error {
		idKey := orgID + ":" + teamID
		t, exists := d.teamsByID[idKey]
		if !exists {
			return store.ErrNotFound
		}

		delete(d.teamsByID, idKey)
		delete(d.teamsBySlug, orgID+":"+t.Slug)
		delete(d.teamMembers, teamID)
		return nil
	})
}

// ListTeamsByOrg lists teams for an organization.
func (s *Store) ListTeamsByOrg(ctx context.Context, orgID string) ([]*store.Team, error) {
	var result []*store.Team
	err := s.read(ctx, func(d *data) error {
		for _, t := range d.teamsByID {
			if t.OrganizationID == orgID {
				result = append(result, cloneTeam(t))
			}
		}
		return nil
	})
	return result, err
}

// AddTeamMember enrolls a user into a team.
func (s *Store) AddTeamMember(ctx context.Context, tm *store.TeamMembership) error {
	return s.write(ctx, func(d *data) error {
		members := d.teamMembers[tm.TeamID]
		if slices.Contains(members, tm.UserID) {
			return store.ErrConflict
		}

		d.teamMembers[tm.TeamID] = append(members, tm.UserID)
		return nil
	})
}

// RemoveTeamMember removes a user from a team.
func (s *Store) RemoveTeamMember(ctx context.Context, teamID, userID string) error {
	return s.write(ctx, func(d *data) error {
		members, exists := d.teamMembers[teamID]
		if !exists || !slices.Contains(members, userID) {
			return store.ErrNotFound
		}

		d.teamMembers[teamID] = slices.DeleteFunc(members, func(u string) bool { return u == userID })
		return nil
	})
}

// ListTeamMembers returns user IDs enrolled in a team.
func (s *Store) ListTeamMembers(ctx context.Context, teamID string) ([]string, error) {
	var result []string
	err := s.read(ctx, func(d *data) error {
		members := d.teamMembers[teamID]
		result = slices.Clone(members)
		return nil
	})
	return result, err
}

// CreateInvitation stores a new invitation.
func (s *Store) CreateInvitation(ctx context.Context, inv *store.Invitation) error {
	return s.write(ctx, func(d *data) error {
		idKey := inv.OrganizationID + ":" + inv.ID
		if _, exists := d.invitationsByID[idKey]; exists {
			return store.ErrConflict
		}
		if _, exists := d.invitationsByHash[inv.TokenHash]; exists {
			return store.ErrConflict
		}

		clone := cloneInvitation(inv)
		d.invitationsByID[idKey] = clone
		d.invitationsByHash[inv.TokenHash] = clone
		return nil
	})
}

// GetInvitationByID retrieves an invitation by ID within an organization.
func (s *Store) GetInvitationByID(ctx context.Context, orgID, id string) (*store.Invitation, error) {
	var result *store.Invitation
	err := s.read(ctx, func(d *data) error {
		key := orgID + ":" + id
		inv, exists := d.invitationsByID[key]
		if !exists {
			return store.ErrNotFound
		}
		result = cloneInvitation(inv)
		return nil
	})
	return result, err
}

// GetInvitationByTokenHash retrieves an invitation by token hash.
func (s *Store) GetInvitationByTokenHash(ctx context.Context, tokenHash string) (*store.Invitation, error) {
	var result *store.Invitation
	err := s.read(ctx, func(d *data) error {
		inv, exists := d.invitationsByHash[tokenHash]
		if !exists {
			return store.ErrNotFound
		}
		result = cloneInvitation(inv)
		return nil
	})
	return result, err
}

// UpdateInvitation updates an invitation record.
func (s *Store) UpdateInvitation(ctx context.Context, inv *store.Invitation) error {
	return s.write(ctx, func(d *data) error {
		idKey := inv.OrganizationID + ":" + inv.ID
		if _, exists := d.invitationsByID[idKey]; !exists {
			return store.ErrNotFound
		}

		clone := cloneInvitation(inv)
		d.invitationsByID[idKey] = clone
		d.invitationsByHash[inv.TokenHash] = clone
		return nil
	})
}

// DeleteInvitation removes an invitation.
func (s *Store) DeleteInvitation(ctx context.Context, orgID, id string) error {
	return s.write(ctx, func(d *data) error {
		key := orgID + ":" + id
		inv, exists := d.invitationsByID[key]
		if !exists {
			return store.ErrNotFound
		}

		delete(d.invitationsByID, key)
		delete(d.invitationsByHash, inv.TokenHash)
		return nil
	})
}

// ListInvitationsByOrg lists all pending invitations for an organization.
func (s *Store) ListInvitationsByOrg(ctx context.Context, orgID string) ([]*store.Invitation, error) {
	var result []*store.Invitation
	err := s.read(ctx, func(d *data) error {
		for _, inv := range d.invitationsByID {
			if inv.OrganizationID == orgID {
				result = append(result, cloneInvitation(inv))
			}
		}
		return nil
	})
	return result, err
}

func cloneOrg(o *store.Organization) *store.Organization {
	if o == nil {
		return nil
	}
	c := *o
	if o.Metadata != nil {
		c.Metadata = maps.Clone(o.Metadata)
	}
	return &c
}

func cloneMembership(m *store.Membership) *store.Membership {
	if m == nil {
		return nil
	}
	c := *m
	return &c
}

func cloneTeam(t *store.Team) *store.Team {
	if t == nil {
		return nil
	}
	c := *t
	return &c
}

func cloneInvitation(inv *store.Invitation) *store.Invitation {
	if inv == nil {
		return nil
	}
	c := *inv
	if inv.AcceptedAt != nil {
		t := *inv.AcceptedAt
		c.AcceptedAt = &t
	}
	return &c
}
