package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/BladiCreator/go-modular-auth-service-accounts/store"
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

func (s *Store) Create(ctx context.Context, sa *store.Record) error {
	scopesJSON, err := json.Marshal(sa.Scopes)
	if err != nil {
		return err
	}
	query := `
		INSERT INTO auth_service_accounts (id, name, description, owner_id, scopes, secret_hash, active, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`
	_, err = s.dbtx(ctx).ExecContext(ctx, query,
		sa.ID, sa.Name, sa.Description, sa.OwnerID, scopesJSON, sa.SecretHash, sa.Active, sa.CreatedAt, sa.UpdatedAt,
	)
	return err
}

func (s *Store) GetByID(ctx context.Context, id string) (*store.Record, error) {
	query := `
		SELECT id, name, description, owner_id, scopes, secret_hash, active, created_at, updated_at
		FROM auth_service_accounts
		WHERE id = $1
	`
	row := s.dbtx(ctx).QueryRowContext(ctx, query, id)

	var sa store.Record
	var scopesRaw []byte
	err := row.Scan(&sa.ID, &sa.Name, &sa.Description, &sa.OwnerID, &scopesRaw, &sa.SecretHash, &sa.Active, &sa.CreatedAt, &sa.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(scopesRaw, &sa.Scopes)
	return &sa, nil
}

func (s *Store) List(ctx context.Context, ownerID string) ([]*store.Record, error) {
	var (
		query string
		args  []any
	)
	if ownerID == "" {
		query = `SELECT id, name, description, owner_id, scopes, secret_hash, active, created_at, updated_at FROM auth_service_accounts`
	} else {
		query = `SELECT id, name, description, owner_id, scopes, secret_hash, active, created_at, updated_at FROM auth_service_accounts WHERE owner_id = $1`
		args = append(args, ownerID)
	}

	rows, err := s.dbtx(ctx).QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []*store.Record
	for rows.Next() {
		var sa store.Record
		var scopesRaw []byte
		if err := rows.Scan(&sa.ID, &sa.Name, &sa.Description, &sa.OwnerID, &scopesRaw, &sa.SecretHash, &sa.Active, &sa.CreatedAt, &sa.UpdatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(scopesRaw, &sa.Scopes)
		list = append(list, &sa)
	}
	return list, rows.Err()
}

func (s *Store) Update(ctx context.Context, sa *store.Record) error {
	scopesJSON, err := json.Marshal(sa.Scopes)
	if err != nil {
		return err
	}
	query := `
		UPDATE auth_service_accounts
		SET name = $2, description = $3, scopes = $4, secret_hash = $5, active = $6, updated_at = $7
		WHERE id = $1
	`
	res, err := s.dbtx(ctx).ExecContext(ctx, query, sa.ID, sa.Name, sa.Description, scopesJSON, sa.SecretHash, sa.Active, sa.UpdatedAt)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (s *Store) Delete(ctx context.Context, id string) error {
	query := `DELETE FROM auth_service_accounts WHERE id = $1`
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
