package postgres

import (
	"context"
	"database/sql"
	"errors"

	"github.com/BladiCreator/go-modular-auth-lastlogin/store"
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

func (s *Store) Save(ctx context.Context, record *store.Record) error {
	query := `
		INSERT INTO auth_last_login (user_id, account_id, method, ip, user_agent, logged_in_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (user_id) DO UPDATE SET
			account_id = EXCLUDED.account_id,
			method = EXCLUDED.method,
			ip = EXCLUDED.ip,
			user_agent = EXCLUDED.user_agent,
			logged_in_at = EXCLUDED.logged_in_at
	`
	_, err := s.dbtx(ctx).ExecContext(ctx, query,
		record.UserID,
		record.AccountID,
		record.Method,
		record.IP,
		record.UserAgent,
		record.LoggedInAt,
	)
	return err
}

func (s *Store) GetByUserID(ctx context.Context, userID string) (*store.Record, error) {
	query := `
		SELECT user_id, account_id, method, ip, user_agent, logged_in_at
		FROM auth_last_login
		WHERE user_id = $1
	`
	row := s.dbtx(ctx).QueryRowContext(ctx, query, userID)

	var rec store.Record
	var accountID, ip, userAgent sql.NullString
	err := row.Scan(
		&rec.UserID,
		&accountID,
		&rec.Method,
		&ip,
		&userAgent,
		&rec.LoggedInAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	rec.AccountID = accountID.String
	rec.IP = ip.String
	rec.UserAgent = userAgent.String
	return &rec, nil
}
