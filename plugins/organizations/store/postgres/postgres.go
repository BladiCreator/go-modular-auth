// Package postgres provides a PostgreSQL implementation of store.Store using database/sql.
package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"

	"github.com/BladiCreator/go-modular-auth-organizations/store"
)

type txKey struct{}

// Store implements store.Store using a standard database/sql connection pool.
type Store struct {
	db *sql.DB
}

var _ store.Store = (*Store)(nil)

// New constructs a new PostgreSQL organization store.
func New(db *sql.DB) *Store {
	return &Store{db: db}
}

func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "unique constraint") ||
		strings.Contains(s, "duplicate key") ||
		strings.Contains(s, "23505")
}

type queryable interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func (s *Store) executor(ctx context.Context) queryable {
	if tx, ok := ctx.Value(txKey{}).(*sql.Tx); ok {
		return tx
	}
	return s.db
}

// Transaction executes fn inside a database transaction.
func (s *Store) Transaction(ctx context.Context, fn func(ctx context.Context) error) error {
	if _, ok := ctx.Value(txKey{}).(*sql.Tx); ok {
		return fn(ctx)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}

	txCtx := context.WithValue(ctx, txKey{}, tx)
	if err := fn(txCtx); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

// CreateOrganization persists a new organization.
func (s *Store) CreateOrganization(ctx context.Context, org *store.Organization) error {
	metaJSON, err := json.Marshal(org.Metadata)
	if err != nil {
		metaJSON = []byte("{}")
	}

	query := `
		INSERT INTO auth_organizations (
			id, name, slug, owner_id, metadata, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7)`

	_, err = s.executor(ctx).ExecContext(ctx, query,
		org.ID, org.Name, org.Slug, org.OwnerID, metaJSON, org.CreatedAt, org.UpdatedAt,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return store.ErrConflict
		}
		return err
	}
	return nil
}

// GetOrganizationByID retrieves an organization by its ID.
func (s *Store) GetOrganizationByID(ctx context.Context, id string) (*store.Organization, error) {
	query := `
		SELECT id, name, slug, owner_id, metadata, created_at, updated_at
		FROM auth_organizations
		WHERE id = $1 LIMIT 1`

	var org store.Organization
	var metaJSON []byte
	err := s.executor(ctx).QueryRowContext(ctx, query, id).Scan(
		&org.ID, &org.Name, &org.Slug, &org.OwnerID, &metaJSON, &org.CreatedAt, &org.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, store.ErrNotFound
		}
		return nil, err
	}
	if len(metaJSON) > 0 {
		_ = json.Unmarshal(metaJSON, &org.Metadata)
	}
	return &org, nil
}

// GetOrganizationBySlug retrieves an organization by its slug.
func (s *Store) GetOrganizationBySlug(ctx context.Context, slug string) (*store.Organization, error) {
	query := `
		SELECT id, name, slug, owner_id, metadata, created_at, updated_at
		FROM auth_organizations
		WHERE slug = $1 LIMIT 1`

	var org store.Organization
	var metaJSON []byte
	err := s.executor(ctx).QueryRowContext(ctx, query, slug).Scan(
		&org.ID, &org.Name, &org.Slug, &org.OwnerID, &metaJSON, &org.CreatedAt, &org.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, store.ErrNotFound
		}
		return nil, err
	}
	if len(metaJSON) > 0 {
		_ = json.Unmarshal(metaJSON, &org.Metadata)
	}
	return &org, nil
}

// UpdateOrganization updates organization details.
func (s *Store) UpdateOrganization(ctx context.Context, org *store.Organization) error {
	metaJSON, err := json.Marshal(org.Metadata)
	if err != nil {
		metaJSON = []byte("{}")
	}

	query := `
		UPDATE auth_organizations
		SET name = $1, slug = $2, owner_id = $3, metadata = $4, updated_at = $5
		WHERE id = $6`

	res, err := s.executor(ctx).ExecContext(ctx, query,
		org.Name, org.Slug, org.OwnerID, metaJSON, org.UpdatedAt, org.ID,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return store.ErrConflict
		}
		return err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return store.ErrNotFound
	}
	return nil
}

// DeleteOrganization removes an organization and cascades delete.
func (s *Store) DeleteOrganization(ctx context.Context, id string) error {
	query := `DELETE FROM auth_organizations WHERE id = $1`
	res, err := s.executor(ctx).ExecContext(ctx, query, id)
	if err != nil {
		return err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return store.ErrNotFound
	}
	return nil
}

// ListOrganizationsByUser returns all organizations where user is an active member.
func (s *Store) ListOrganizationsByUser(ctx context.Context, userID string) ([]*store.Organization, error) {
	query := `
		SELECT o.id, o.name, o.slug, o.owner_id, o.metadata, o.created_at, o.updated_at
		FROM auth_organizations o
		INNER JOIN auth_organization_memberships m ON o.id = m.organization_id
		WHERE m.user_id = $1 AND m.status = 'active'
		ORDER BY o.name ASC`

	rows, err := s.executor(ctx).QueryContext(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []*store.Organization
	for rows.Next() {
		var org store.Organization
		var metaJSON []byte
		if err := rows.Scan(
			&org.ID, &org.Name, &org.Slug, &org.OwnerID, &metaJSON, &org.CreatedAt, &org.UpdatedAt,
		); err != nil {
			return nil, err
		}
		if len(metaJSON) > 0 {
			_ = json.Unmarshal(metaJSON, &org.Metadata)
		}
		result = append(result, &org)
	}
	return result, rows.Err()
}

// CreateMembership persists a new membership.
func (s *Store) CreateMembership(ctx context.Context, m *store.Membership) error {
	query := `
		INSERT INTO auth_organization_memberships (
			id, organization_id, user_id, role, status, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7)`

	_, err := s.executor(ctx).ExecContext(ctx, query,
		m.ID, m.OrganizationID, m.UserID, string(m.Role), string(m.Status), m.CreatedAt, m.UpdatedAt,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return store.ErrConflict
		}
		return err
	}
	return nil
}

// GetMembership retrieves a member record.
func (s *Store) GetMembership(ctx context.Context, orgID, userID string) (*store.Membership, error) {
	query := `
		SELECT id, organization_id, user_id, role, status, created_at, updated_at
		FROM auth_organization_memberships
		WHERE organization_id = $1 AND user_id = $2 LIMIT 1`

	var m store.Membership
	var r, st string
	err := s.executor(ctx).QueryRowContext(ctx, query, orgID, userID).Scan(
		&m.ID, &m.OrganizationID, &m.UserID, &r, &st, &m.CreatedAt, &m.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, store.ErrNotFound
		}
		return nil, err
	}
	m.Role = store.Role(r)
	m.Status = store.MembershipStatus(st)
	return &m, nil
}

// UpdateMembership updates a membership.
func (s *Store) UpdateMembership(ctx context.Context, m *store.Membership) error {
	query := `
		UPDATE auth_organization_memberships
		SET role = $1, status = $2, updated_at = $3
		WHERE organization_id = $4 AND user_id = $5`

	res, err := s.executor(ctx).ExecContext(ctx, query,
		string(m.Role), string(m.Status), m.UpdatedAt, m.OrganizationID, m.UserID,
	)
	if err != nil {
		return err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return store.ErrNotFound
	}
	return nil
}

// DeleteMembership deletes a membership.
func (s *Store) DeleteMembership(ctx context.Context, orgID, userID string) error {
	query := `DELETE FROM auth_organization_memberships WHERE organization_id = $1 AND user_id = $2`
	res, err := s.executor(ctx).ExecContext(ctx, query, orgID, userID)
	if err != nil {
		return err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return store.ErrNotFound
	}
	return nil
}

// ListMembershipsByOrg lists memberships for an organization.
func (s *Store) ListMembershipsByOrg(ctx context.Context, orgID string) ([]*store.Membership, error) {
	query := `
		SELECT id, organization_id, user_id, role, status, created_at, updated_at
		FROM auth_organization_memberships
		WHERE organization_id = $1
		ORDER BY created_at ASC`

	rows, err := s.executor(ctx).QueryContext(ctx, query, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []*store.Membership
	for rows.Next() {
		var m store.Membership
		var r, st string
		if err := rows.Scan(
			&m.ID, &m.OrganizationID, &m.UserID, &r, &st, &m.CreatedAt, &m.UpdatedAt,
		); err != nil {
			return nil, err
		}
		m.Role = store.Role(r)
		m.Status = store.MembershipStatus(st)
		result = append(result, &m)
	}
	return result, rows.Err()
}

// CreateTeam persists a new team.
func (s *Store) CreateTeam(ctx context.Context, t *store.Team) error {
	query := `
		INSERT INTO auth_organization_teams (
			id, organization_id, name, slug, description, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7)`

	_, err := s.executor(ctx).ExecContext(ctx, query,
		t.ID, t.OrganizationID, t.Name, t.Slug, t.Description, t.CreatedAt, t.UpdatedAt,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return store.ErrConflict
		}
		return err
	}
	return nil
}

// GetTeamByID retrieves a team by ID.
func (s *Store) GetTeamByID(ctx context.Context, orgID, teamID string) (*store.Team, error) {
	query := `
		SELECT id, organization_id, name, slug, description, created_at, updated_at
		FROM auth_organization_teams
		WHERE organization_id = $1 AND id = $2 LIMIT 1`

	var t store.Team
	err := s.executor(ctx).QueryRowContext(ctx, query, orgID, teamID).Scan(
		&t.ID, &t.OrganizationID, &t.Name, &t.Slug, &t.Description, &t.CreatedAt, &t.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, store.ErrNotFound
		}
		return nil, err
	}
	return &t, nil
}

// GetTeamBySlug retrieves a team by slug.
func (s *Store) GetTeamBySlug(ctx context.Context, orgID, slug string) (*store.Team, error) {
	query := `
		SELECT id, organization_id, name, slug, description, created_at, updated_at
		FROM auth_organization_teams
		WHERE organization_id = $1 AND slug = $2 LIMIT 1`

	var t store.Team
	err := s.executor(ctx).QueryRowContext(ctx, query, orgID, slug).Scan(
		&t.ID, &t.OrganizationID, &t.Name, &t.Slug, &t.Description, &t.CreatedAt, &t.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, store.ErrNotFound
		}
		return nil, err
	}
	return &t, nil
}

// UpdateTeam updates team details.
func (s *Store) UpdateTeam(ctx context.Context, t *store.Team) error {
	query := `
		UPDATE auth_organization_teams
		SET name = $1, slug = $2, description = $3, updated_at = $4
		WHERE organization_id = $5 AND id = $6`

	res, err := s.executor(ctx).ExecContext(ctx, query,
		t.Name, t.Slug, t.Description, t.UpdatedAt, t.OrganizationID, t.ID,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return store.ErrConflict
		}
		return err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return store.ErrNotFound
	}
	return nil
}

// DeleteTeam removes a team.
func (s *Store) DeleteTeam(ctx context.Context, orgID, teamID string) error {
	query := `DELETE FROM auth_organization_teams WHERE organization_id = $1 AND id = $2`
	res, err := s.executor(ctx).ExecContext(ctx, query, orgID, teamID)
	if err != nil {
		return err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return store.ErrNotFound
	}
	return nil
}

// ListTeamsByOrg lists teams for an organization.
func (s *Store) ListTeamsByOrg(ctx context.Context, orgID string) ([]*store.Team, error) {
	query := `
		SELECT id, organization_id, name, slug, description, created_at, updated_at
		FROM auth_organization_teams
		WHERE organization_id = $1
		ORDER BY created_at ASC`

	rows, err := s.executor(ctx).QueryContext(ctx, query, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []*store.Team
	for rows.Next() {
		var t store.Team
		if err := rows.Scan(
			&t.ID, &t.OrganizationID, &t.Name, &t.Slug, &t.Description, &t.CreatedAt, &t.UpdatedAt,
		); err != nil {
			return nil, err
		}
		result = append(result, &t)
	}
	return result, rows.Err()
}

// AddTeamMember enrolls a member into a team.
func (s *Store) AddTeamMember(ctx context.Context, tm *store.TeamMembership) error {
	query := `
		INSERT INTO auth_organization_team_members (team_id, user_id, created_at)
		VALUES ($1, $2, $3)`

	_, err := s.executor(ctx).ExecContext(ctx, query, tm.TeamID, tm.UserID, tm.CreatedAt)
	if err != nil {
		if isUniqueViolation(err) {
			return store.ErrConflict
		}
		return err
	}
	return nil
}

// RemoveTeamMember disenrolls a member from a team.
func (s *Store) RemoveTeamMember(ctx context.Context, teamID, userID string) error {
	query := `DELETE FROM auth_organization_team_members WHERE team_id = $1 AND user_id = $2`
	res, err := s.executor(ctx).ExecContext(ctx, query, teamID, userID)
	if err != nil {
		return err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return store.ErrNotFound
	}
	return nil
}

// ListTeamMembers returns user IDs enrolled in a team.
func (s *Store) ListTeamMembers(ctx context.Context, teamID string) ([]string, error) {
	query := `SELECT user_id FROM auth_organization_team_members WHERE team_id = $1 ORDER BY created_at ASC`
	rows, err := s.executor(ctx).QueryContext(ctx, query, teamID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []string
	for rows.Next() {
		var userID string
		if err := rows.Scan(&userID); err != nil {
			return nil, err
		}
		result = append(result, userID)
	}
	return result, rows.Err()
}

// CreateInvitation persists an invitation record.
func (s *Store) CreateInvitation(ctx context.Context, inv *store.Invitation) error {
	query := `
		INSERT INTO auth_organization_invitations (
			id, organization_id, email, role, inviter_user_id, token_hash, expires_at, accepted_at, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`

	_, err := s.executor(ctx).ExecContext(ctx, query,
		inv.ID, inv.OrganizationID, inv.Email, string(inv.Role), inv.InviterUserID,
		inv.TokenHash, inv.ExpiresAt, inv.AcceptedAt, inv.CreatedAt,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return store.ErrConflict
		}
		return err
	}
	return nil
}

// GetInvitationByID retrieves an invitation by ID within an organization.
func (s *Store) GetInvitationByID(ctx context.Context, orgID, id string) (*store.Invitation, error) {
	query := `
		SELECT id, organization_id, email, role, inviter_user_id, token_hash, expires_at, accepted_at, created_at
		FROM auth_organization_invitations
		WHERE organization_id = $1 AND id = $2 LIMIT 1`

	var inv store.Invitation
	var r string
	err := s.executor(ctx).QueryRowContext(ctx, query, orgID, id).Scan(
		&inv.ID, &inv.OrganizationID, &inv.Email, &r, &inv.InviterUserID,
		&inv.TokenHash, &inv.ExpiresAt, &inv.AcceptedAt, &inv.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, store.ErrNotFound
		}
		return nil, err
	}
	inv.Role = store.Role(r)
	return &inv, nil
}

// GetInvitationByTokenHash retrieves an invitation by its token hash.
func (s *Store) GetInvitationByTokenHash(ctx context.Context, tokenHash string) (*store.Invitation, error) {
	query := `
		SELECT id, organization_id, email, role, inviter_user_id, token_hash, expires_at, accepted_at, created_at
		FROM auth_organization_invitations
		WHERE token_hash = $1 LIMIT 1`

	var inv store.Invitation
	var r string
	err := s.executor(ctx).QueryRowContext(ctx, query, tokenHash).Scan(
		&inv.ID, &inv.OrganizationID, &inv.Email, &r, &inv.InviterUserID,
		&inv.TokenHash, &inv.ExpiresAt, &inv.AcceptedAt, &inv.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, store.ErrNotFound
		}
		return nil, err
	}
	inv.Role = store.Role(r)
	return &inv, nil
}

// UpdateInvitation updates an invitation record.
func (s *Store) UpdateInvitation(ctx context.Context, inv *store.Invitation) error {
	query := `
		UPDATE auth_organization_invitations
		SET accepted_at = $1
		WHERE id = $2`

	res, err := s.executor(ctx).ExecContext(ctx, query, inv.AcceptedAt, inv.ID)
	if err != nil {
		return err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return store.ErrNotFound
	}
	return nil
}

// DeleteInvitation deletes an invitation.
func (s *Store) DeleteInvitation(ctx context.Context, orgID, id string) error {
	query := `DELETE FROM auth_organization_invitations WHERE organization_id = $1 AND id = $2`
	res, err := s.executor(ctx).ExecContext(ctx, query, orgID, id)
	if err != nil {
		return err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return store.ErrNotFound
	}
	return nil
}

// ListInvitationsByOrg lists pending invitations for an organization.
func (s *Store) ListInvitationsByOrg(ctx context.Context, orgID string) ([]*store.Invitation, error) {
	query := `
		SELECT id, organization_id, email, role, inviter_user_id, token_hash, expires_at, accepted_at, created_at
		FROM auth_organization_invitations
		WHERE organization_id = $1
		ORDER BY created_at DESC`

	rows, err := s.executor(ctx).QueryContext(ctx, query, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []*store.Invitation
	for rows.Next() {
		var inv store.Invitation
		var r string
		if err := rows.Scan(
			&inv.ID, &inv.OrganizationID, &inv.Email, &r, &inv.InviterUserID,
			&inv.TokenHash, &inv.ExpiresAt, &inv.AcceptedAt, &inv.CreatedAt,
		); err != nil {
			return nil, err
		}
		inv.Role = store.Role(r)
		result = append(result, &inv)
	}
	return result, rows.Err()
}
