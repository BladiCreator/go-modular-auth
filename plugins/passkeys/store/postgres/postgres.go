package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/BladiCreator/go-modular-auth-passkeys/store"
	"github.com/go-webauthn/webauthn/protocol"
)

// PostgresStore implements store.Store backed by PostgreSQL.
type PostgresStore struct {
	db *sql.DB
}

var _ store.Store = (*PostgresStore)(nil)

// New constructs a new PostgreSQL passkey store.
func New(db *sql.DB) *PostgresStore {
	return &PostgresStore{db: db}
}

// SaveCredential persists a newly created passkey.
func (s *PostgresStore) SaveCredential(ctx context.Context, c *store.Credential) error {
	transportsJSON, err := json.Marshal(c.Transports)
	if err != nil {
		transportsJSON = []byte("[]")
	}

	query := `
		INSERT INTO auth_passkeys (
			id, credential_id, user_id, friendly_name, public_key, attestation_type,
			aaguid, sign_count, clone_warning, attachment, transports, user_present,
			user_verified, backup_eligible, backup_state, created_at, updated_at, last_used_at, revoked_at
		) VALUES (
			$1, $2, $3, $4, $5, $6,
			$7, $8, $9, $10, $11, $12,
			$13, $14, $15, $16, $17, $18, $19
		)`

	_, err = s.db.ExecContext(ctx, query,
		c.ID, c.CredentialID, c.UserID, c.FriendlyName, c.PublicKey, c.AttestationType,
		c.AAGUID, c.SignCount, c.CloneWarning, string(c.Attachment), transportsJSON, c.UserPresent,
		c.UserVerified, c.BackupEligible, c.BackupState, c.CreatedAt, c.UpdatedAt, c.LastUsedAt, c.RevokedAt,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return store.ErrConflict
		}
		return err
	}
	return nil
}

// GetCredentialByID retrieves a non-revoked passkey by binary credential ID.
func (s *PostgresStore) GetCredentialByID(ctx context.Context, credentialID []byte) (*store.Credential, error) {
	query := `
		SELECT
			id, credential_id, user_id, friendly_name, public_key, attestation_type,
			aaguid, sign_count, clone_warning, attachment, transports, user_present,
			user_verified, backup_eligible, backup_state, created_at, updated_at, last_used_at, revoked_at
		FROM auth_passkeys
		WHERE credential_id = $1 AND revoked_at IS NULL`

	row := s.db.QueryRowContext(ctx, query, credentialID)
	return scanCredential(row)
}

// ListCredentialsByUser retrieves all non-revoked passkeys for a given user.
func (s *PostgresStore) ListCredentialsByUser(ctx context.Context, userID string) ([]*store.Credential, error) {
	query := `
		SELECT
			id, credential_id, user_id, friendly_name, public_key, attestation_type,
			aaguid, sign_count, clone_warning, attachment, transports, user_present,
			user_verified, backup_eligible, backup_state, created_at, updated_at, last_used_at, revoked_at
		FROM auth_passkeys
		WHERE user_id = $1 AND revoked_at IS NULL
		ORDER BY created_at DESC`

	rows, err := s.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []*store.Credential
	for rows.Next() {
		c, err := scanCredential(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, c)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

// UpdateCredential updates mutable fields on an existing credential.
func (s *PostgresStore) UpdateCredential(ctx context.Context, c *store.Credential) error {
	query := `
		UPDATE auth_passkeys
		SET friendly_name = $1, sign_count = $2, clone_warning = $3,
		    updated_at = $4, last_used_at = $5, backup_state = $6
		WHERE credential_id = $7 AND revoked_at IS NULL`

	res, err := s.db.ExecContext(ctx, query,
		c.FriendlyName, c.SignCount, c.CloneWarning, c.UpdatedAt, c.LastUsedAt, c.BackupState, c.CredentialID,
	)
	if err != nil {
		return err
	}
	rowsAffected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return store.ErrNotFound
	}
	return nil
}

// DeleteCredential marks a passkey as revoked or removes it.
func (s *PostgresStore) DeleteCredential(ctx context.Context, credentialID []byte) error {
	query := `UPDATE auth_passkeys SET revoked_at = $1 WHERE credential_id = $2 AND revoked_at IS NULL`
	now := time.Now()
	res, err := s.db.ExecContext(ctx, query, now, credentialID)
	if err != nil {
		return err
	}
	rowsAffected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return store.ErrNotFound
	}
	return nil
}

type scanner interface {
	Scan(dest ...any) error
}

func scanCredential(s scanner) (*store.Credential, error) {
	var c store.Credential
	var attachmentStr string
	var transportsJSON []byte

	err := s.Scan(
		&c.ID, &c.CredentialID, &c.UserID, &c.FriendlyName, &c.PublicKey, &c.AttestationType,
		&c.AAGUID, &c.SignCount, &c.CloneWarning, &attachmentStr, &transportsJSON, &c.UserPresent,
		&c.UserVerified, &c.BackupEligible, &c.BackupState, &c.CreatedAt, &c.UpdatedAt, &c.LastUsedAt, &c.RevokedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, store.ErrNotFound
		}
		return nil, err
	}

	c.Attachment = protocol.AuthenticatorAttachment(attachmentStr)
	if len(transportsJSON) > 0 {
		var transports []protocol.AuthenticatorTransport
		if err := json.Unmarshal(transportsJSON, &transports); err == nil {
			c.Transports = transports
		}
	}

	return &c, nil
}

func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, sql.ErrNoRows) == false && (contains(err.Error(), "23505") || contains(err.Error(), "unique constraint"))
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || searchSubstr(s, substr))
}

func searchSubstr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
