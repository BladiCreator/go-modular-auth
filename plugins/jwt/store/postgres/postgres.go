package postgres

import (
	"context"
	"database/sql"
	"time"

	"github.com/BladiCreator/go-modular-auth-jwt/store"
)

// Store implements store.Store against a PostgreSQL database using database/sql.
type Store struct {
	db *sql.DB
}

var _ store.Store = (*Store)(nil)

// New constructs a new PostgreSQL revocation store.
func New(db *sql.DB) *Store {
	return &Store{db: db}
}

// RevokeToken persists an individual token revocation record.
func (s *Store) RevokeToken(ctx context.Context, record *store.RevocationRecord) error {
	const query = `
		INSERT INTO jwt_token_revocations (jti, subject, reason, expires_at, revoked_at)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (jti) DO UPDATE
		SET reason = EXCLUDED.reason,
		    expires_at = EXCLUDED.expires_at,
		    revoked_at = EXCLUDED.revoked_at;
	`
	_, err := s.db.ExecContext(ctx, query,
		record.JTI,
		record.Subject,
		record.Reason,
		record.ExpiresAt,
		record.RevokedAt,
	)
	return err
}

// IsTokenRevoked checks whether the given JTI is recorded and not yet past its expiration.
func (s *Store) IsTokenRevoked(ctx context.Context, jti string) (bool, error) {
	const query = `
		SELECT EXISTS(
			SELECT 1 FROM jwt_token_revocations
			WHERE jti = $1 AND expires_at > $2
		);
	`
	var exists bool
	err := s.db.QueryRowContext(ctx, query, jti, time.Now()).Scan(&exists)
	if err != nil {
		return false, err
	}
	return exists, nil
}

// RevokeSubject records or updates a subject cutoff revocation.
func (s *Store) RevokeSubject(ctx context.Context, record *store.SubjectRevocationRecord) error {
	const query = `
		INSERT INTO jwt_subject_revocations (subject, cutoff, reason, revoked_at)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (subject) DO UPDATE
		SET cutoff = GREATEST(jwt_subject_revocations.cutoff, EXCLUDED.cutoff),
		    reason = EXCLUDED.reason,
		    revoked_at = EXCLUDED.revoked_at;
	`
	_, err := s.db.ExecContext(ctx, query,
		record.Subject,
		record.Cutoff,
		record.Reason,
		record.RevokedAt,
	)
	return err
}

// IsSubjectRevoked checks whether a subject revocation exists whose cutoff timestamp is >= issuedAt.
func (s *Store) IsSubjectRevoked(ctx context.Context, subject string, issuedAt time.Time) (bool, error) {
	const query = `
		SELECT EXISTS(
			SELECT 1 FROM jwt_subject_revocations
			WHERE subject = $1 AND cutoff >= $2
		);
	`
	var exists bool
	err := s.db.QueryRowContext(ctx, query, subject, issuedAt).Scan(&exists)
	if err != nil {
		return false, err
	}
	return exists, nil
}

// DeleteExpired purges expired individual token revocations from the database.
func (s *Store) DeleteExpired(ctx context.Context, now time.Time) (int, error) {
	const query = `
		DELETE FROM jwt_token_revocations
		WHERE expires_at <= $1;
	`
	res, err := s.db.ExecContext(ctx, query, now)
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}
	return int(n), nil
}
