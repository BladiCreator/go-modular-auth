package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/BladiCreator/go-modular-auth-scim/store"
	"github.com/BladiCreator/go-modular-auth/store/sqltx"
)

type Store struct {
	db *sql.DB
}

var _ store.Store = (*Store)(nil)

func New(db *sql.DB) *Store {
	return &Store{db: db}
}

func (s *Store) dbtx(ctx context.Context) sqltx.DBTX {
	return sqltx.Executor(ctx, s.db)
}

func (s *Store) SaveUserMetadata(ctx context.Context, meta *store.UserMetadata) error {
	query := `
		INSERT INTO auth_scim_user_metadata (user_id, external_id, active, given_name, family_name, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (user_id) DO UPDATE SET
			external_id = EXCLUDED.external_id,
			active = EXCLUDED.active,
			given_name = EXCLUDED.given_name,
			family_name = EXCLUDED.family_name,
			updated_at = EXCLUDED.updated_at
	`
	_, err := s.dbtx(ctx).ExecContext(ctx, query,
		meta.UserID, meta.ExternalID, meta.Active, meta.GivenName, meta.FamilyName, meta.CreatedAt, meta.UpdatedAt,
	)
	return err
}

func (s *Store) GetUserMetadata(ctx context.Context, userID string) (*store.UserMetadata, error) {
	query := `
		SELECT user_id, external_id, active, given_name, family_name, created_at, updated_at
		FROM auth_scim_user_metadata
		WHERE user_id = $1
	`
	row := s.dbtx(ctx).QueryRowContext(ctx, query, userID)

	var m store.UserMetadata
	var extID, givenName, familyName sql.NullString
	err := row.Scan(&m.UserID, &extID, &m.Active, &givenName, &familyName, &m.CreatedAt, &m.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	m.ExternalID = extID.String
	m.GivenName = givenName.String
	m.FamilyName = familyName.String
	return &m, nil
}

func (s *Store) GetUserMetadataByExternalID(ctx context.Context, externalID string) (*store.UserMetadata, error) {
	query := `
		SELECT user_id, external_id, active, given_name, family_name, created_at, updated_at
		FROM auth_scim_user_metadata
		WHERE external_id = $1
	`
	row := s.dbtx(ctx).QueryRowContext(ctx, query, externalID)

	var m store.UserMetadata
	var extID, givenName, familyName sql.NullString
	err := row.Scan(&m.UserID, &extID, &m.Active, &givenName, &familyName, &m.CreatedAt, &m.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	m.ExternalID = extID.String
	m.GivenName = givenName.String
	m.FamilyName = familyName.String
	return &m, nil
}

func (s *Store) DeleteUserMetadata(ctx context.Context, userID string) error {
	query := `DELETE FROM auth_scim_user_metadata WHERE user_id = $1`
	_, err := s.dbtx(ctx).ExecContext(ctx, query, userID)
	return err
}

func (s *Store) CreateGroup(ctx context.Context, grp *store.GroupRecord) error {
	membersJSON, err := json.Marshal(grp.MemberIDs)
	if err != nil {
		return err
	}
	query := `
		INSERT INTO auth_scim_groups (id, display_name, members, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5)
	`
	_, err = s.dbtx(ctx).ExecContext(ctx, query, grp.ID, grp.DisplayName, membersJSON, grp.CreatedAt, grp.UpdatedAt)
	return err
}

func (s *Store) GetGroup(ctx context.Context, id string) (*store.GroupRecord, error) {
	query := `
		SELECT id, display_name, members, created_at, updated_at
		FROM auth_scim_groups
		WHERE id = $1
	`
	row := s.dbtx(ctx).QueryRowContext(ctx, query, id)

	var g store.GroupRecord
	var membersRaw []byte
	err := row.Scan(&g.ID, &g.DisplayName, &membersRaw, &g.CreatedAt, &g.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(membersRaw, &g.MemberIDs)
	return &g, nil
}

func (s *Store) ListGroups(ctx context.Context) ([]*store.GroupRecord, error) {
	query := `SELECT id, display_name, members, created_at, updated_at FROM auth_scim_groups`
	rows, err := s.dbtx(ctx).QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []*store.GroupRecord
	for rows.Next() {
		var g store.GroupRecord
		var membersRaw []byte
		if err := rows.Scan(&g.ID, &g.DisplayName, &membersRaw, &g.CreatedAt, &g.UpdatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(membersRaw, &g.MemberIDs)
		list = append(list, &g)
	}
	return list, rows.Err()
}

func (s *Store) UpdateGroup(ctx context.Context, grp *store.GroupRecord) error {
	membersJSON, err := json.Marshal(grp.MemberIDs)
	if err != nil {
		return err
	}
	query := `
		UPDATE auth_scim_groups
		SET display_name = $2, members = $3, updated_at = $4
		WHERE id = $1
	`
	res, err := s.dbtx(ctx).ExecContext(ctx, query, grp.ID, grp.DisplayName, membersJSON, grp.UpdatedAt)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (s *Store) DeleteGroup(ctx context.Context, id string) error {
	query := `DELETE FROM auth_scim_groups WHERE id = $1`
	res, err := s.dbtx(ctx).ExecContext(ctx, query, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return store.ErrNotFound
	}
	return nil
}
