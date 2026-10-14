// Package bridge implements a store.Store adapter on top of adapter.Adapter.
//
// This allows GoModularAuth core services (SignIn, CreateSession, etc.) to run
// transparently against any generic schema-driven database adapter (Memory, Postgres,
// SQLite, MySQL) while maintaining 100% backward compatibility.
package bridge

import (
	"context"
	"errors"
	"time"

	"github.com/BladiCreator/go-modular-auth/account"
	"github.com/BladiCreator/go-modular-auth/adapter"
	"github.com/BladiCreator/go-modular-auth/credential"
	"github.com/BladiCreator/go-modular-auth/schema"
	"github.com/BladiCreator/go-modular-auth/session"
	"github.com/BladiCreator/go-modular-auth/store"
	"github.com/BladiCreator/go-modular-auth/user"
	"github.com/BladiCreator/go-modular-auth/verification"
)

type bridgeStore struct {
	ad adapter.Adapter
}

// New wraps an adapter.Adapter into a store.Store.
func New(ad adapter.Adapter) store.Store {
	return &bridgeStore{ad: ad}
}

func (b *bridgeStore) Users() store.UserStore {
	return &userStore{ad: b.ad}
}

func (b *bridgeStore) Accounts() store.AccountStore {
	return &accountStore{ad: b.ad}
}

func (b *bridgeStore) Credentials() store.CredentialStore {
	return &credentialStore{ad: b.ad}
}

func (b *bridgeStore) Sessions() store.SessionStore {
	return &sessionStore{ad: b.ad}
}

func (b *bridgeStore) Tokens() store.TokenStore {
	return &tokenStore{ad: b.ad}
}

func (b *bridgeStore) Transaction(ctx context.Context, fn func(ctx context.Context) error) error {
	return b.ad.Transaction(ctx, func(txCtx context.Context, tx adapter.Adapter) error {
		txBridge := &bridgeStore{ad: tx}
		// Pass child context if needed or execute directly
		_ = txBridge
		return fn(txCtx)
	})
}

// --- UserStore ---

type userStore struct {
	ad adapter.Adapter
}

func (s *userStore) Create(ctx context.Context, u *user.User) error {
	row := map[string]any{
		"id":             u.ID,
		"email":          u.Email,
		"email_verified": u.EmailVerified,
		"created_at":     u.CreatedAt,
		"updated_at":     u.UpdatedAt,
	}
	_, err := s.ad.Create(ctx, schema.ModelUsers, row)
	if errors.Is(err, adapter.ErrConflict) {
		return store.ErrConflict
	}
	return err
}

func (s *userStore) GetByID(ctx context.Context, id string) (*user.User, error) {
	row, err := s.ad.FindOne(ctx, schema.ModelUsers, []adapter.Condition{adapter.Eq("id", id)})
	if err != nil {
		if errors.Is(err, adapter.ErrNotFound) {
			return nil, store.ErrNotFound
		}
		return nil, err
	}
	return toUser(row), nil
}

func (s *userStore) GetByEmail(ctx context.Context, email string) (*user.User, error) {
	row, err := s.ad.FindOne(ctx, schema.ModelUsers, []adapter.Condition{adapter.Eq("email", email)})
	if err != nil {
		if errors.Is(err, adapter.ErrNotFound) {
			return nil, store.ErrNotFound
		}
		return nil, err
	}
	return toUser(row), nil
}

func (s *userStore) Update(ctx context.Context, u *user.User) error {
	count, err := s.ad.Update(ctx, schema.ModelUsers, []adapter.Condition{adapter.Eq("id", u.ID)}, map[string]any{
		"email":          u.Email,
		"email_verified": u.EmailVerified,
		"updated_at":     u.UpdatedAt,
	})
	if err != nil {
		if errors.Is(err, adapter.ErrConflict) {
			return store.ErrConflict
		}
		return err
	}
	if count == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (s *userStore) Delete(ctx context.Context, id string) error {
	count, err := s.ad.Delete(ctx, schema.ModelUsers, []adapter.Condition{adapter.Eq("id", id)})
	if err != nil {
		return err
	}
	if count == 0 {
		return store.ErrNotFound
	}
	return nil
}

func toUser(r map[string]any) *user.User {
	u := &user.User{
		ID:    getString(r, "id"),
		Email: getString(r, "email"),
	}
	if b, ok := r["email_verified"].(bool); ok {
		u.EmailVerified = b
	}
	if t, ok := r["created_at"].(time.Time); ok {
		u.CreatedAt = t
	}
	if t, ok := r["updated_at"].(time.Time); ok {
		u.UpdatedAt = t
	}
	return u
}

// --- AccountStore ---

type accountStore struct {
	ad adapter.Adapter
}

func (s *accountStore) Create(ctx context.Context, a *account.Account) error {
	row := map[string]any{
		"id":          a.ID,
		"user_id":     a.UserID,
		"provider":    a.Provider,
		"provider_id": a.ProviderID,
		"created_at":  a.CreatedAt,
		"updated_at":  a.UpdatedAt,
	}
	_, err := s.ad.Create(ctx, schema.ModelAccounts, row)
	if errors.Is(err, adapter.ErrConflict) {
		return store.ErrConflict
	}
	return err
}

func (s *accountStore) GetByID(ctx context.Context, id string) (*account.Account, error) {
	row, err := s.ad.FindOne(ctx, schema.ModelAccounts, []adapter.Condition{adapter.Eq("id", id)})
	if err != nil {
		if errors.Is(err, adapter.ErrNotFound) {
			return nil, store.ErrNotFound
		}
		return nil, err
	}
	return toAccount(row), nil
}

func (s *accountStore) GetByProvider(ctx context.Context, provider, providerID string) (*account.Account, error) {
	row, err := s.ad.FindOne(ctx, schema.ModelAccounts, []adapter.Condition{
		adapter.Eq("provider", provider),
		adapter.Eq("provider_id", providerID),
	})
	if err != nil {
		if errors.Is(err, adapter.ErrNotFound) {
			return nil, store.ErrNotFound
		}
		return nil, err
	}
	return toAccount(row), nil
}

func (s *accountStore) ListByUser(ctx context.Context, userID string) ([]*account.Account, error) {
	rows, err := s.ad.FindMany(ctx, adapter.Query{
		Model: schema.ModelAccounts,
		Where: []adapter.Condition{adapter.Eq("user_id", userID)},
	})
	if err != nil {
		return nil, err
	}
	res := make([]*account.Account, len(rows))
	for i, r := range rows {
		res[i] = toAccount(r)
	}
	return res, nil
}

func (s *accountStore) Delete(ctx context.Context, id string) error {
	count, err := s.ad.Delete(ctx, schema.ModelAccounts, []adapter.Condition{adapter.Eq("id", id)})
	if err != nil {
		return err
	}
	if count == 0 {
		return store.ErrNotFound
	}
	return nil
}

func toAccount(r map[string]any) *account.Account {
	return &account.Account{
		ID:         getString(r, "id"),
		UserID:     getString(r, "user_id"),
		Provider:   getString(r, "provider"),
		ProviderID: getString(r, "provider_id"),
		CreatedAt:  getTime(r, "created_at"),
		UpdatedAt:  getTime(r, "updated_at"),
	}
}

// --- CredentialStore ---

type credentialStore struct {
	ad adapter.Adapter
}

func (s *credentialStore) Create(ctx context.Context, c *credential.Credential) error {
	row := map[string]any{
		"id":         c.ID,
		"user_id":    c.UserID,
		"account_id": c.AccountID,
		"type":       string(c.Type),
		"secret":     c.Secret,
		"created_at": c.CreatedAt,
		"updated_at": c.UpdatedAt,
		"revoked_at": c.RevokedAt,
	}
	_, err := s.ad.Create(ctx, schema.ModelCredentials, row)
	if errors.Is(err, adapter.ErrConflict) {
		return store.ErrConflict
	}
	return err
}

func (s *credentialStore) GetByID(ctx context.Context, id string) (*credential.Credential, error) {
	row, err := s.ad.FindOne(ctx, schema.ModelCredentials, []adapter.Condition{adapter.Eq("id", id)})
	if err != nil {
		if errors.Is(err, adapter.ErrNotFound) {
			return nil, store.ErrNotFound
		}
		return nil, err
	}
	return toCredential(row), nil
}

func (s *credentialStore) GetActiveByAccount(ctx context.Context, accountID string, t credential.Type) (*credential.Credential, error) {
	row, err := s.ad.FindOne(ctx, schema.ModelCredentials, []adapter.Condition{
		adapter.Eq("account_id", accountID),
		adapter.Eq("type", string(t)),
		adapter.IsNull("revoked_at"),
	})
	if err != nil {
		if errors.Is(err, adapter.ErrNotFound) {
			return nil, store.ErrNotFound
		}
		return nil, err
	}
	return toCredential(row), nil
}

func (s *credentialStore) ListByUser(ctx context.Context, userID string) ([]*credential.Credential, error) {
	rows, err := s.ad.FindMany(ctx, adapter.Query{
		Model: schema.ModelCredentials,
		Where: []adapter.Condition{adapter.Eq("user_id", userID)},
	})
	if err != nil {
		return nil, err
	}
	res := make([]*credential.Credential, len(rows))
	for i, r := range rows {
		res[i] = toCredential(r)
	}
	return res, nil
}

func (s *credentialStore) Update(ctx context.Context, c *credential.Credential) error {
	count, err := s.ad.Update(ctx, schema.ModelCredentials, []adapter.Condition{adapter.Eq("id", c.ID)}, map[string]any{
		"secret":     c.Secret,
		"updated_at": c.UpdatedAt,
		"revoked_at": c.RevokedAt,
	})
	if err != nil {
		return err
	}
	if count == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (s *credentialStore) Revoke(ctx context.Context, id string, at time.Time) error {
	count, err := s.ad.Update(ctx, schema.ModelCredentials, []adapter.Condition{adapter.Eq("id", id)}, map[string]any{
		"revoked_at": at,
	})
	if err != nil {
		return err
	}
	if count == 0 {
		return store.ErrNotFound
	}
	return nil
}

func toCredential(r map[string]any) *credential.Credential {
	c := &credential.Credential{
		ID:        getString(r, "id"),
		UserID:    getString(r, "user_id"),
		AccountID: getString(r, "account_id"),
		Type:      credential.Type(getString(r, "type")),
		Secret:    getString(r, "secret"),
		CreatedAt: getTime(r, "created_at"),
		UpdatedAt: getTime(r, "updated_at"),
	}
	if t, ok := r["revoked_at"].(time.Time); ok {
		c.RevokedAt = &t
	}
	return c
}

// --- SessionStore ---

type sessionStore struct {
	ad adapter.Adapter
}

func (s *sessionStore) Create(ctx context.Context, sess *session.Session) error {
	row := map[string]any{
		"id":         sess.ID,
		"user_id":    sess.UserID,
		"token_hash": sess.TokenHash,
		"ip_address": sess.IPAddress,
		"user_agent": sess.UserAgent,
		"expires_at": sess.ExpiresAt,
		"revoked_at": sess.RevokedAt,
		"created_at": sess.CreatedAt,
	}
	_, err := s.ad.Create(ctx, schema.ModelSessions, row)
	if errors.Is(err, adapter.ErrConflict) {
		return store.ErrConflict
	}
	return err
}

func (s *sessionStore) GetByID(ctx context.Context, id string) (*session.Session, error) {
	row, err := s.ad.FindOne(ctx, schema.ModelSessions, []adapter.Condition{adapter.Eq("id", id)})
	if err != nil {
		if errors.Is(err, adapter.ErrNotFound) {
			return nil, store.ErrNotFound
		}
		return nil, err
	}
	return toSession(row), nil
}

func (s *sessionStore) GetByTokenHash(ctx context.Context, tokenHash string) (*session.Session, error) {
	row, err := s.ad.FindOne(ctx, schema.ModelSessions, []adapter.Condition{adapter.Eq("token_hash", tokenHash)})
	if err != nil {
		if errors.Is(err, adapter.ErrNotFound) {
			return nil, store.ErrNotFound
		}
		return nil, err
	}
	return toSession(row), nil
}

func (s *sessionStore) ListByUser(ctx context.Context, userID string) ([]*session.Session, error) {
	rows, err := s.ad.FindMany(ctx, adapter.Query{
		Model: schema.ModelSessions,
		Where: []adapter.Condition{adapter.Eq("user_id", userID)},
	})
	if err != nil {
		return nil, err
	}
	res := make([]*session.Session, len(rows))
	for i, r := range rows {
		res[i] = toSession(r)
	}
	return res, nil
}

func (s *sessionStore) Revoke(ctx context.Context, id string, at time.Time) error {
	count, err := s.ad.Update(ctx, schema.ModelSessions, []adapter.Condition{adapter.Eq("id", id)}, map[string]any{
		"revoked_at": at,
	})
	if err != nil {
		return err
	}
	if count == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (s *sessionStore) RevokeByUser(ctx context.Context, userID string, at time.Time) ([]*session.Session, error) {
	sessions, err := s.ListByUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	var revoked []*session.Session
	for _, sess := range sessions {
		if sess.RevokedAt == nil {
			_ = s.Revoke(ctx, sess.ID, at)
			sess.RevokedAt = &at
			revoked = append(revoked, sess)
		}
	}
	return revoked, nil
}

func (s *sessionStore) DeleteExpired(ctx context.Context, before time.Time) (int, error) {
	count, err := s.ad.Delete(ctx, schema.ModelSessions, []adapter.Condition{adapter.Lt("expires_at", before)})
	return int(count), err
}

func toSession(r map[string]any) *session.Session {
	sess := &session.Session{
		ID:        getString(r, "id"),
		UserID:    getString(r, "user_id"),
		TokenHash: getString(r, "token_hash"),
		IPAddress: getString(r, "ip_address"),
		UserAgent: getString(r, "user_agent"),
		ExpiresAt: getTime(r, "expires_at"),
		CreatedAt: getTime(r, "created_at"),
	}
	if t, ok := r["revoked_at"].(time.Time); ok {
		sess.RevokedAt = &t
	}
	return sess
}

// --- TokenStore ---

type tokenStore struct {
	ad adapter.Adapter
}

func (s *tokenStore) Create(ctx context.Context, t *verification.Token) error {
	row := map[string]any{
		"id":         t.ID,
		"purpose":    string(t.Purpose),
		"subject":    t.Subject,
		"token_hash": t.TokenHash,
		"expires_at": t.ExpiresAt,
		"used_at":    t.UsedAt,
		"created_at": t.CreatedAt,
	}
	_, err := s.ad.Create(ctx, schema.ModelVerifications, row)
	if errors.Is(err, adapter.ErrConflict) {
		return store.ErrConflict
	}
	return err
}

func (s *tokenStore) GetByHash(ctx context.Context, tokenHash string) (*verification.Token, error) {
	row, err := s.ad.FindOne(ctx, schema.ModelVerifications, []adapter.Condition{adapter.Eq("token_hash", tokenHash)})
	if err != nil {
		if errors.Is(err, adapter.ErrNotFound) {
			return nil, store.ErrNotFound
		}
		return nil, err
	}
	return toToken(row), nil
}

func (s *tokenStore) MarkUsed(ctx context.Context, id string, at time.Time) error {
	count, err := s.ad.Update(ctx, schema.ModelVerifications, []adapter.Condition{
		adapter.Eq("id", id),
		adapter.IsNull("used_at"),
	}, map[string]any{
		"used_at": at,
	})
	if err != nil {
		return err
	}
	if count == 0 {
		return store.ErrConflict
	}
	return nil
}

func (s *tokenStore) DeleteBySubject(ctx context.Context, purpose verification.Purpose, subject string) error {
	_, err := s.ad.Delete(ctx, schema.ModelVerifications, []adapter.Condition{
		adapter.Eq("purpose", string(purpose)),
		adapter.Eq("subject", subject),
	})
	return err
}

func (s *tokenStore) DeleteExpired(ctx context.Context, before time.Time) (int, error) {
	count, err := s.ad.Delete(ctx, schema.ModelVerifications, []adapter.Condition{adapter.Lt("expires_at", before)})
	return int(count), err
}

func toToken(r map[string]any) *verification.Token {
	t := &verification.Token{
		ID:        getString(r, "id"),
		Purpose:   verification.Purpose(getString(r, "purpose")),
		Subject:   getString(r, "subject"),
		TokenHash: getString(r, "token_hash"),
		ExpiresAt: getTime(r, "expires_at"),
		CreatedAt: getTime(r, "created_at"),
	}
	if u, ok := r["used_at"].(time.Time); ok {
		t.UsedAt = &u
	}
	return t
}

func getString(r map[string]any, k string) string {
	if s, ok := r[k].(string); ok {
		return s
	}
	return ""
}

func getTime(r map[string]any, k string) time.Time {
	if t, ok := r[k].(time.Time); ok {
		return t
	}
	return time.Time{}
}
