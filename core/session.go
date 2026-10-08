package auth

import (
	"context"
	"errors"

	"github.com/BladiCreator/go-modular-auth/internal/secure"
	"github.com/BladiCreator/go-modular-auth/session"
	"github.com/BladiCreator/go-modular-auth/store"
	"github.com/BladiCreator/go-modular-auth/user"
)

// SessionResult is a validated session together with its user.
type SessionResult struct {
	Session *session.Session
	User    *user.User
}

// Principal returns the authenticated identity of the session.
func (r *SessionResult) Principal() Principal {
	return Principal{Subject: r.User.ID, Type: PrincipalUser}
}

// SessionOptions carries optional metadata recorded with a new session.
type SessionOptions struct {
	IPAddress string
	UserAgent string
}

// IssuedSession is a newly created session and its plaintext token. The
// token is returned exactly once: hand it to the client and discard it.
type IssuedSession struct {
	Session *session.Session
	Token   string
}

// CreateSession issues a session for an existing user. It is the entry point
// for plugins that authenticate by other means (OAuth, passkeys, magic link).
func (a *Auth) CreateSession(ctx context.Context, userID string, opts SessionOptions) (*IssuedSession, error) {
	var issued *IssuedSession
	err := a.store.Transaction(ctx, func(ctx context.Context) error {
		if _, err := a.store.Users().GetByID(ctx, userID); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return ErrUserNotFound
			}
			return err
		}
		var err error
		issued, err = a.newSession(ctx, userID, opts)
		return err
	})
	if err != nil {
		return nil, err
	}
	a.afterSessionCreated(ctx, issued.Session)
	return issued, nil
}

// newSession persists a session. It must run inside a Store transaction and
// must be followed by afterSessionCreated once the transaction commits.
func (a *Auth) newSession(ctx context.Context, userID string, opts SessionOptions) (*IssuedSession, error) {
	now := a.Now()
	token := secure.NewToken()
	s := &session.Session{
		ID:        secure.NewID(),
		UserID:    userID,
		TokenHash: secure.HashToken(token),
		IPAddress: opts.IPAddress,
		UserAgent: opts.UserAgent,
		ExpiresAt: now.Add(a.cfg.Session.TTL),
		CreatedAt: now,
	}
	if err := a.hooks.beforeSessionCreate.run(ctx, s); err != nil {
		return nil, err
	}
	if err := a.store.Sessions().Create(ctx, s); err != nil {
		return nil, err
	}
	return &IssuedSession{Session: s, Token: token}, nil
}

func (a *Auth) afterSessionCreated(ctx context.Context, s *session.Session) {
	a.cacheSession(ctx, s)
	a.publish(ctx, EventSessionCreated, s.UserID, s)
}

// GetSession resolves an opaque token. It returns (nil, nil) when the token
// does not identify a valid (existing, unexpired, unrevoked) session.
func (a *Auth) GetSession(ctx context.Context, token string) (*SessionResult, error) {
	if token == "" {
		return nil, nil
	}
	hash := secure.HashToken(token)
	now := a.Now()

	s := a.cachedSession(ctx, hash)
	if s == nil {
		var err error
		s, err = a.store.Sessions().GetByTokenHash(ctx, hash)
		if errors.Is(err, store.ErrNotFound) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		if s.Valid(now) {
			a.cacheSession(ctx, s)
		}
	}
	if !s.Valid(now) {
		a.invalidateSessions(ctx, s)
		return nil, nil
	}

	u, err := a.GetUser(ctx, s.UserID)
	if err != nil {
		return nil, err
	}
	if u == nil { // user deleted: the session is orphaned
		a.invalidateSessions(ctx, s)
		return nil, nil
	}
	return &SessionResult{Session: s, User: u}, nil
}

// RequireSession is like GetSession but returns ErrUnauthenticated when no
// valid session exists.
func (a *Auth) RequireSession(ctx context.Context, token string) (*SessionResult, error) {
	res, err := a.GetSession(ctx, token)
	if err != nil {
		return nil, err
	}
	if res == nil {
		return nil, ErrUnauthenticated
	}
	return res, nil
}

// RevokeSession revokes a session by ID: Store first, then cache invalidation.
// Revoking an already revoked session is a no-op.
func (a *Auth) RevokeSession(ctx context.Context, sessionID string) error {
	s, err := a.store.Sessions().GetByID(ctx, sessionID)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if s.Revoked() {
		a.invalidateSessions(ctx, s)
		return nil
	}
	now := a.Now()
	if err := a.store.Sessions().Revoke(ctx, s.ID, now); err != nil {
		return err
	}
	s.RevokedAt = &now
	a.invalidateSessions(ctx, s)
	a.publish(ctx, EventSessionRevoked, s.UserID, s)
	return nil
}

// RevokeUserSessions revokes every active session of a user except the one
// with ID exceptSessionID (pass "" to revoke all).
func (a *Auth) RevokeUserSessions(ctx context.Context, userID, exceptSessionID string) error {
	var revoked []*session.Session
	err := a.store.Transaction(ctx, func(ctx context.Context) error {
		var err error
		revoked, err = a.revokeUserSessions(ctx, userID, exceptSessionID)
		return err
	})
	if err != nil {
		return err
	}
	a.afterSessionsRevoked(ctx, revoked)
	return nil
}

// revokeUserSessions runs inside a transaction; call afterSessionsRevoked after commit.
func (a *Auth) revokeUserSessions(ctx context.Context, userID, except string) ([]*session.Session, error) {
	now := a.Now()
	if except == "" {
		return a.store.Sessions().RevokeByUser(ctx, userID, now)
	}
	all, err := a.store.Sessions().ListByUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	var revoked []*session.Session
	for _, s := range all {
		if s.ID == except || s.Revoked() {
			continue
		}
		if err := a.store.Sessions().Revoke(ctx, s.ID, now); err != nil {
			return nil, err
		}
		s.RevokedAt = &now
		revoked = append(revoked, s)
	}
	return revoked, nil
}

func (a *Auth) afterSessionsRevoked(ctx context.Context, revoked []*session.Session) {
	a.invalidateSessions(ctx, revoked...)
	for _, s := range revoked {
		a.publish(ctx, EventSessionRevoked, s.UserID, s)
	}
}
