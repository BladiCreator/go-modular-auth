package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/BladiCreator/go-modular-auth-agent/store"
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

func (s *Store) CreateAgent(ctx context.Context, a *store.AgentRecord) error {
	scopesJSON, err := json.Marshal(a.Scopes)
	if err != nil {
		return err
	}
	metaJSON, err := json.Marshal(a.Metadata)
	if err != nil {
		return err
	}

	query := `
		INSERT INTO auth_agents (id, name, description, owner_id, scopes, metadata, active, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`
	_, err = s.dbtx(ctx).ExecContext(ctx, query,
		a.ID, a.Name, a.Description, a.OwnerID, scopesJSON, metaJSON, a.Active, a.CreatedAt, a.UpdatedAt,
	)
	return err
}

func (s *Store) GetAgent(ctx context.Context, id string) (*store.AgentRecord, error) {
	query := `
		SELECT id, name, description, owner_id, scopes, metadata, active, created_at, updated_at
		FROM auth_agents
		WHERE id = $1
	`
	row := s.dbtx(ctx).QueryRowContext(ctx, query, id)

	var a store.AgentRecord
	var scopesRaw, metaRaw []byte
	err := row.Scan(&a.ID, &a.Name, &a.Description, &a.OwnerID, &scopesRaw, &metaRaw, &a.Active, &a.CreatedAt, &a.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(scopesRaw, &a.Scopes)
	_ = json.Unmarshal(metaRaw, &a.Metadata)
	return &a, nil
}

func (s *Store) ListAgentsByOwner(ctx context.Context, ownerID string) ([]*store.AgentRecord, error) {
	query := `
		SELECT id, name, description, owner_id, scopes, metadata, active, created_at, updated_at
		FROM auth_agents
		WHERE owner_id = $1
	`
	rows, err := s.dbtx(ctx).QueryContext(ctx, query, ownerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []*store.AgentRecord
	for rows.Next() {
		var a store.AgentRecord
		var scopesRaw, metaRaw []byte
		if err := rows.Scan(&a.ID, &a.Name, &a.Description, &a.OwnerID, &scopesRaw, &metaRaw, &a.Active, &a.CreatedAt, &a.UpdatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(scopesRaw, &a.Scopes)
		_ = json.Unmarshal(metaRaw, &a.Metadata)
		list = append(list, &a)
	}
	return list, rows.Err()
}

func (s *Store) UpdateAgent(ctx context.Context, a *store.AgentRecord) error {
	scopesJSON, err := json.Marshal(a.Scopes)
	if err != nil {
		return err
	}
	metaJSON, err := json.Marshal(a.Metadata)
	if err != nil {
		return err
	}

	query := `
		UPDATE auth_agents
		SET name = $2, description = $3, scopes = $4, metadata = $5, active = $6, updated_at = $7
		WHERE id = $1
	`
	res, err := s.dbtx(ctx).ExecContext(ctx, query, a.ID, a.Name, a.Description, scopesJSON, metaJSON, a.Active, a.UpdatedAt)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (s *Store) DeleteAgent(ctx context.Context, id string) error {
	query := `DELETE FROM auth_agents WHERE id = $1`
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

func (s *Store) SaveCredential(ctx context.Context, c *store.CredentialRecord) error {
	query := `
		INSERT INTO auth_agent_credentials (id, agent_id, token_hash, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5)
	`
	_, err := s.dbtx(ctx).ExecContext(ctx, query, c.ID, c.AgentID, c.TokenHash, c.ExpiresAt, c.CreatedAt)
	return err
}

func (s *Store) GetCredentialByHash(ctx context.Context, hash string) (*store.CredentialRecord, error) {
	query := `
		SELECT id, agent_id, token_hash, expires_at, created_at
		FROM auth_agent_credentials
		WHERE token_hash = $1
	`
	row := s.dbtx(ctx).QueryRowContext(ctx, query, hash)
	var c store.CredentialRecord
	err := row.Scan(&c.ID, &c.AgentID, &c.TokenHash, &c.ExpiresAt, &c.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func (s *Store) RevokeCredential(ctx context.Context, id string) error {
	query := `DELETE FROM auth_agent_credentials WHERE id = $1`
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

func (s *Store) DeleteExpiredCredentials(ctx context.Context, before time.Time) error {
	query := `DELETE FROM auth_agent_credentials WHERE expires_at < $1`
	_, err := s.dbtx(ctx).ExecContext(ctx, query, before)
	return err
}
