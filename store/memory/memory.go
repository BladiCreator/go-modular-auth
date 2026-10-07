// Package memory provides an in-memory store.Store implementation intended
// for unit tests, local development and examples. It is not durable and not
// distributed; do not use it in production.
//
// Transactions are serialized and implemented with snapshot/rollback: writes
// performed outside a transaction wait for running transactions to finish, so
// a rollback never discards concurrent non-transactional writes.
package memory

import (
	"cmp"
	"context"
	"maps"
	"slices"
	"sync"
	"time"

	"github.com/BladiCreator/go-modular-auth/account"
	"github.com/BladiCreator/go-modular-auth/credential"
	"github.com/BladiCreator/go-modular-auth/session"
	"github.com/BladiCreator/go-modular-auth/store"
	"github.com/BladiCreator/go-modular-auth/user"
	"github.com/BladiCreator/go-modular-auth/verification"
)

// Store is an in-memory store.Store. The zero value is not usable; call New.
type Store struct {
	txMu sync.Mutex   // serializes transactions and non-transactional writes
	mu   sync.RWMutex // guards data
	data data
}

// data holds every table. Stored values are never mutated in place: updates
// replace the pointer with a fresh copy, so a shallow clone is a valid snapshot.
type data struct {
	users          map[string]*user.User
	usersByEmail   map[string]string
	accounts       map[string]*account.Account
	accountsByProv map[string]string
	credentials    map[string]*credential.Credential
	sessions       map[string]*session.Session
	sessionsByHash map[string]string
	tokens         map[string]*verification.Token
	tokensByHash   map[string]string
}

func newData() data {
	return data{
		users:          map[string]*user.User{},
		usersByEmail:   map[string]string{},
		accounts:       map[string]*account.Account{},
		accountsByProv: map[string]string{},
		credentials:    map[string]*credential.Credential{},
		sessions:       map[string]*session.Session{},
		sessionsByHash: map[string]string{},
		tokens:         map[string]*verification.Token{},
		tokensByHash:   map[string]string{},
	}
}

func (d data) clone() data {
	return data{
		users:          maps.Clone(d.users),
		usersByEmail:   maps.Clone(d.usersByEmail),
		accounts:       maps.Clone(d.accounts),
		accountsByProv: maps.Clone(d.accountsByProv),
		credentials:    maps.Clone(d.credentials),
		sessions:       maps.Clone(d.sessions),
		sessionsByHash: maps.Clone(d.sessionsByHash),
		tokens:         maps.Clone(d.tokens),
		tokensByHash:   maps.Clone(d.tokensByHash),
	}
}

var _ store.Store = (*Store)(nil)

// New returns an empty in-memory store.
func New() *Store {
	return &Store{data: newData()}
}

type txKey struct{ s *Store }

func (s *Store) inTx(ctx context.Context) bool {
	v, _ := ctx.Value(txKey{s}).(bool)
	return v
}

// Transaction runs fn atomically, rolling back every change if fn fails.
func (s *Store) Transaction(ctx context.Context, fn func(ctx context.Context) error) error {
	if s.inTx(ctx) {
		return fn(ctx)
	}
	s.txMu.Lock()
	defer s.txMu.Unlock()

	s.mu.RLock()
	snapshot := s.data.clone()
	s.mu.RUnlock()

	if err := fn(context.WithValue(ctx, txKey{s}, true)); err != nil {
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

func ptr[T any](v T) *T { return &v }

// Users returns the user store.
func (s *Store) Users() store.UserStore { return userStore{s} }

// Accounts returns the account store.
func (s *Store) Accounts() store.AccountStore { return accountStore{s} }

// Credentials returns the credential store.
func (s *Store) Credentials() store.CredentialStore { return credentialStore{s} }

// Sessions returns the session store.
func (s *Store) Sessions() store.SessionStore { return sessionStore{s} }

// Tokens returns the verification token store.
func (s *Store) Tokens() store.TokenStore { return tokenStore{s} }

// ---- users ----

type userStore struct{ s *Store }

func (r userStore) Create(ctx context.Context, u *user.User) error {
	return r.s.write(ctx, func(d *data) error {
		if _, ok := d.users[u.ID]; ok {
			return store.ErrConflict
		}
		if _, ok := d.usersByEmail[u.Email]; ok {
			return store.ErrConflict
		}
		d.users[u.ID] = ptr(*u)
		d.usersByEmail[u.Email] = u.ID
		return nil
	})
}

func (r userStore) GetByID(ctx context.Context, id string) (*user.User, error) {
	var out *user.User
	err := r.s.read(ctx, func(d *data) error {
		u, ok := d.users[id]
		if !ok {
			return store.ErrNotFound
		}
		out = ptr(*u)
		return nil
	})
	return out, err
}

func (r userStore) GetByEmail(ctx context.Context, email string) (*user.User, error) {
	var out *user.User
	err := r.s.read(ctx, func(d *data) error {
		id, ok := d.usersByEmail[email]
		if !ok {
			return store.ErrNotFound
		}
		out = ptr(*d.users[id])
		return nil
	})
	return out, err
}

func (r userStore) Update(ctx context.Context, u *user.User) error {
	return r.s.write(ctx, func(d *data) error {
		old, ok := d.users[u.ID]
		if !ok {
			return store.ErrNotFound
		}
		if old.Email != u.Email {
			if _, taken := d.usersByEmail[u.Email]; taken {
				return store.ErrConflict
			}
			delete(d.usersByEmail, old.Email)
			d.usersByEmail[u.Email] = u.ID
		}
		d.users[u.ID] = ptr(*u)
		return nil
	})
}

func (r userStore) Delete(ctx context.Context, id string) error {
	return r.s.write(ctx, func(d *data) error {
		u, ok := d.users[id]
		if !ok {
			return store.ErrNotFound
		}
		delete(d.usersByEmail, u.Email)
		delete(d.users, id)
		return nil
	})
}

// ---- accounts ----

type accountStore struct{ s *Store }

func provKey(provider, providerID string) string { return provider + "\x00" + providerID }

func (r accountStore) Create(ctx context.Context, a *account.Account) error {
	return r.s.write(ctx, func(d *data) error {
		k := provKey(a.Provider, a.ProviderID)
		if _, ok := d.accounts[a.ID]; ok {
			return store.ErrConflict
		}
		if _, ok := d.accountsByProv[k]; ok {
			return store.ErrConflict
		}
		d.accounts[a.ID] = ptr(*a)
		d.accountsByProv[k] = a.ID
		return nil
	})
}

func (r accountStore) GetByID(ctx context.Context, id string) (*account.Account, error) {
	var out *account.Account
	err := r.s.read(ctx, func(d *data) error {
		a, ok := d.accounts[id]
		if !ok {
			return store.ErrNotFound
		}
		out = ptr(*a)
		return nil
	})
	return out, err
}

func (r accountStore) GetByProvider(ctx context.Context, provider, providerID string) (*account.Account, error) {
	var out *account.Account
	err := r.s.read(ctx, func(d *data) error {
		id, ok := d.accountsByProv[provKey(provider, providerID)]
		if !ok {
			return store.ErrNotFound
		}
		out = ptr(*d.accounts[id])
		return nil
	})
	return out, err
}

func (r accountStore) ListByUser(ctx context.Context, userID string) ([]*account.Account, error) {
	var out []*account.Account
	err := r.s.read(ctx, func(d *data) error {
		for _, a := range d.accounts {
			if a.UserID == userID {
				out = append(out, ptr(*a))
			}
		}
		slices.SortFunc(out, func(a, b *account.Account) int { return a.CreatedAt.Compare(b.CreatedAt) })
		return nil
	})
	return out, err
}

func (r accountStore) Delete(ctx context.Context, id string) error {
	return r.s.write(ctx, func(d *data) error {
		a, ok := d.accounts[id]
		if !ok {
			return store.ErrNotFound
		}
		delete(d.accountsByProv, provKey(a.Provider, a.ProviderID))
		delete(d.accounts, id)
		return nil
	})
}

// ---- credentials ----

type credentialStore struct{ s *Store }

func (r credentialStore) Create(ctx context.Context, c *credential.Credential) error {
	return r.s.write(ctx, func(d *data) error {
		if _, ok := d.credentials[c.ID]; ok {
			return store.ErrConflict
		}
		d.credentials[c.ID] = ptr(*c)
		return nil
	})
}

func (r credentialStore) GetByID(ctx context.Context, id string) (*credential.Credential, error) {
	var out *credential.Credential
	err := r.s.read(ctx, func(d *data) error {
		c, ok := d.credentials[id]
		if !ok {
			return store.ErrNotFound
		}
		out = ptr(*c)
		return nil
	})
	return out, err
}

func (r credentialStore) GetActiveByAccount(ctx context.Context, accountID string, t credential.Type) (*credential.Credential, error) {
	var out *credential.Credential
	err := r.s.read(ctx, func(d *data) error {
		for _, c := range d.credentials {
			if c.AccountID == accountID && c.Type == t && c.Active() {
				if out == nil || c.CreatedAt.After(out.CreatedAt) {
					out = ptr(*c)
				}
			}
		}
		if out == nil {
			return store.ErrNotFound
		}
		return nil
	})
	return out, err
}

func (r credentialStore) ListByUser(ctx context.Context, userID string) ([]*credential.Credential, error) {
	var out []*credential.Credential
	err := r.s.read(ctx, func(d *data) error {
		for _, c := range d.credentials {
			if c.UserID == userID {
				out = append(out, ptr(*c))
			}
		}
		slices.SortFunc(out, func(a, b *credential.Credential) int { return a.CreatedAt.Compare(b.CreatedAt) })
		return nil
	})
	return out, err
}

func (r credentialStore) Update(ctx context.Context, c *credential.Credential) error {
	return r.s.write(ctx, func(d *data) error {
		if _, ok := d.credentials[c.ID]; !ok {
			return store.ErrNotFound
		}
		d.credentials[c.ID] = ptr(*c)
		return nil
	})
}

func (r credentialStore) Revoke(ctx context.Context, id string, at time.Time) error {
	return r.s.write(ctx, func(d *data) error {
		c, ok := d.credentials[id]
		if !ok {
			return store.ErrNotFound
		}
		if c.RevokedAt != nil {
			return nil
		}
		cp := ptr(*c)
		cp.RevokedAt = ptr(at)
		d.credentials[id] = cp
		return nil
	})
}

// ---- sessions ----

type sessionStore struct{ s *Store }

func (r sessionStore) Create(ctx context.Context, s *session.Session) error {
	return r.s.write(ctx, func(d *data) error {
		if _, ok := d.sessions[s.ID]; ok {
			return store.ErrConflict
		}
		if _, ok := d.sessionsByHash[s.TokenHash]; ok {
			return store.ErrConflict
		}
		d.sessions[s.ID] = ptr(*s)
		d.sessionsByHash[s.TokenHash] = s.ID
		return nil
	})
}

func (r sessionStore) GetByID(ctx context.Context, id string) (*session.Session, error) {
	var out *session.Session
	err := r.s.read(ctx, func(d *data) error {
		s, ok := d.sessions[id]
		if !ok {
			return store.ErrNotFound
		}
		out = ptr(*s)
		return nil
	})
	return out, err
}

func (r sessionStore) GetByTokenHash(ctx context.Context, tokenHash string) (*session.Session, error) {
	var out *session.Session
	err := r.s.read(ctx, func(d *data) error {
		id, ok := d.sessionsByHash[tokenHash]
		if !ok {
			return store.ErrNotFound
		}
		out = ptr(*d.sessions[id])
		return nil
	})
	return out, err
}

func (r sessionStore) ListByUser(ctx context.Context, userID string) ([]*session.Session, error) {
	var out []*session.Session
	err := r.s.read(ctx, func(d *data) error {
		for _, s := range d.sessions {
			if s.UserID == userID {
				out = append(out, ptr(*s))
			}
		}
		slices.SortFunc(out, func(a, b *session.Session) int {
			return cmp.Or(a.CreatedAt.Compare(b.CreatedAt), cmp.Compare(a.ID, b.ID))
		})
		return nil
	})
	return out, err
}

func (r sessionStore) Revoke(ctx context.Context, id string, at time.Time) error {
	return r.s.write(ctx, func(d *data) error {
		s, ok := d.sessions[id]
		if !ok {
			return store.ErrNotFound
		}
		if s.RevokedAt != nil {
			return nil
		}
		cp := ptr(*s)
		cp.RevokedAt = ptr(at)
		d.sessions[id] = cp
		return nil
	})
}

func (r sessionStore) RevokeByUser(ctx context.Context, userID string, at time.Time) ([]*session.Session, error) {
	var out []*session.Session
	err := r.s.write(ctx, func(d *data) error {
		for id, s := range d.sessions {
			if s.UserID != userID || s.RevokedAt != nil {
				continue
			}
			cp := ptr(*s)
			cp.RevokedAt = ptr(at)
			d.sessions[id] = cp
			out = append(out, ptr(*cp))
		}
		return nil
	})
	return out, err
}

func (r sessionStore) DeleteExpired(ctx context.Context, before time.Time) (int, error) {
	n := 0
	err := r.s.write(ctx, func(d *data) error {
		for id, s := range d.sessions {
			if s.ExpiresAt.Before(before) {
				delete(d.sessionsByHash, s.TokenHash)
				delete(d.sessions, id)
				n++
			}
		}
		return nil
	})
	return n, err
}

// ---- verification tokens ----

type tokenStore struct{ s *Store }

func (r tokenStore) Create(ctx context.Context, t *verification.Token) error {
	return r.s.write(ctx, func(d *data) error {
		if _, ok := d.tokens[t.ID]; ok {
			return store.ErrConflict
		}
		if _, ok := d.tokensByHash[t.TokenHash]; ok {
			return store.ErrConflict
		}
		d.tokens[t.ID] = ptr(*t)
		d.tokensByHash[t.TokenHash] = t.ID
		return nil
	})
}

func (r tokenStore) GetByHash(ctx context.Context, tokenHash string) (*verification.Token, error) {
	var out *verification.Token
	err := r.s.read(ctx, func(d *data) error {
		id, ok := d.tokensByHash[tokenHash]
		if !ok {
			return store.ErrNotFound
		}
		out = ptr(*d.tokens[id])
		return nil
	})
	return out, err
}

func (r tokenStore) MarkUsed(ctx context.Context, id string, at time.Time) error {
	return r.s.write(ctx, func(d *data) error {
		t, ok := d.tokens[id]
		if !ok {
			return store.ErrNotFound
		}
		if t.UsedAt != nil {
			return store.ErrConflict
		}
		cp := ptr(*t)
		cp.UsedAt = ptr(at)
		d.tokens[id] = cp
		return nil
	})
}

func (r tokenStore) DeleteBySubject(ctx context.Context, purpose verification.Purpose, subject string) error {
	return r.s.write(ctx, func(d *data) error {
		for id, t := range d.tokens {
			if t.Purpose == purpose && t.Subject == subject {
				delete(d.tokensByHash, t.TokenHash)
				delete(d.tokens, id)
			}
		}
		return nil
	})
}

func (r tokenStore) DeleteExpired(ctx context.Context, before time.Time) (int, error) {
	n := 0
	err := r.s.write(ctx, func(d *data) error {
		for id, t := range d.tokens {
			if t.ExpiresAt.Before(before) {
				delete(d.tokensByHash, t.TokenHash)
				delete(d.tokens, id)
				n++
			}
		}
		return nil
	})
	return n, err
}
