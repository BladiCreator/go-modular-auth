package auth

import (
	"context"
	"errors"
	"time"

	"github.com/BladiCreator/go-modular-auth/internal/secure"
	"github.com/BladiCreator/go-modular-auth/store"
	"github.com/BladiCreator/go-modular-auth/verification"
)

// IssueToken creates a single-use verification token for subject and returns
// its plaintext value. Only the hash is persisted. Plugins (magic link, OTP,
// one-time token, device authorization) reuse this primitive.
func (a *Auth) IssueToken(ctx context.Context, purpose verification.Purpose, subject string, ttl time.Duration) (string, error) {
	if purpose == "" || subject == "" || ttl <= 0 {
		return "", errors.New("auth: IssueToken requires purpose, subject and a positive ttl")
	}
	now := a.Now()
	token := secure.NewToken()
	t := &verification.Token{
		ID:        secure.NewID(),
		Purpose:   purpose,
		Subject:   subject,
		TokenHash: secure.HashToken(token),
		ExpiresAt: now.Add(ttl),
		CreatedAt: now,
	}
	if err := a.store.Tokens().Create(ctx, t); err != nil {
		return "", err
	}
	return token, nil
}

// ConsumeToken validates and atomically consumes a token issued for purpose.
// Unknown, expired, already used or wrong-purpose tokens all yield
// ErrInvalidToken, so callers cannot distinguish them.
func (a *Auth) ConsumeToken(ctx context.Context, purpose verification.Purpose, token string) (*verification.Token, error) {
	if token == "" {
		return nil, ErrInvalidToken
	}
	t, err := a.store.Tokens().GetByHash(ctx, secure.HashToken(token))
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrInvalidToken
	}
	if err != nil {
		return nil, err
	}
	now := a.Now()
	if t.Purpose != purpose || t.Used() || t.Expired(now) {
		return nil, ErrInvalidToken
	}
	if err := a.store.Tokens().MarkUsed(ctx, t.ID, now); err != nil {
		if errors.Is(err, store.ErrConflict) || errors.Is(err, store.ErrNotFound) {
			return nil, ErrInvalidToken
		}
		return nil, err
	}
	t.UsedAt = &now
	return t, nil
}

// RevokeTokens deletes every outstanding token of purpose issued to subject.
func (a *Auth) RevokeTokens(ctx context.Context, purpose verification.Purpose, subject string) error {
	return a.store.Tokens().DeleteBySubject(ctx, purpose, subject)
}
