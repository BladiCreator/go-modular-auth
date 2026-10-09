package oidcprovider

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	sdk "github.com/BladiCreator/go-modular-auth/plugin-sdk"
	"github.com/BladiCreator/go-modular-auth/user"
	"github.com/BladiCreator/go-modular-auth-oidc-provider/discovery"
	"github.com/BladiCreator/go-modular-auth-oidc-provider/jwks"
)

var (
	ErrUserNotFound   = errors.New("oidc: user not found")
	ErrInvalidUser    = errors.New("oidc: invalid user")
	ErrSigningFailed  = errors.New("oidc: token signing failed")
	ErrKeyUnavailable = errors.New("oidc: private key unavailable")
)

type OIDCProvider interface {
	GetDiscovery() *discovery.Document
	GetJWKS(ctx context.Context) (*jwks.JWKS, error)
	IssueIDToken(ctx context.Context, u *user.User, clientID, nonce string, ttl time.Duration) (string, error)
	GetUserInfo(ctx context.Context, userID string) (map[string]any, error)
}

type service struct {
	ctx *sdk.Context
	cfg Config
}

var _ OIDCProvider = (*service)(nil)

func newService(ctx *sdk.Context, cfg Config) *service {
	return &service{
		ctx: ctx,
		cfg: cfg,
	}
}

func (s *service) GetDiscovery() *discovery.Document {
	return s.cfg.Discovery
}

func (s *service) GetJWKS(ctx context.Context) (*jwks.JWKS, error) {
	if s.cfg.PrivateKey == nil {
		return nil, ErrKeyUnavailable
	}

	jwk := jwks.FromRSAPublicKey(&s.cfg.PrivateKey.PublicKey, s.cfg.KeyID, "RS256")
	return &jwks.JWKS{
		Keys: []jwks.JWK{jwk},
	}, nil
}

type idTokenHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

type idTokenClaims struct {
	Issuer        string `json:"iss"`
	Subject       string `json:"sub"`
	Audience      string `json:"aud"`
	Expiration    int64  `json:"exp"`
	IssuedAt      int64  `json:"iat"`
	Nonce         string `json:"nonce,omitempty"`
	Email         string `json:"email,omitempty"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name,omitempty"`
}

func (s *service) IssueIDToken(ctx context.Context, u *user.User, clientID, nonce string, ttl time.Duration) (string, error) {
	if u == nil || u.ID == "" {
		return "", ErrInvalidUser
	}
	if s.cfg.PrivateKey == nil {
		return "", ErrKeyUnavailable
	}
	if ttl <= 0 {
		ttl = s.cfg.DefaultTTL
	}

	now := s.ctx.Now()
	header := idTokenHeader{
		Alg: "RS256",
		Typ: "JWT",
		Kid: s.cfg.KeyID,
	}

	claims := idTokenClaims{
		Issuer:        s.cfg.Issuer,
		Subject:       u.ID,
		Audience:      clientID,
		Expiration:    now.Add(ttl).Unix(),
		IssuedAt:      now.Unix(),
		Nonce:         nonce,
		Email:         u.Email,
		EmailVerified: u.EmailVerified,
	}

	hJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	cJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	encodedHeader := base64.RawURLEncoding.EncodeToString(hJSON)
	encodedClaims := base64.RawURLEncoding.EncodeToString(cJSON)
	signingInput := fmt.Sprintf("%s.%s", encodedHeader, encodedClaims)

	hasher := sha256.New()
	hasher.Write([]byte(signingInput))
	digest := hasher.Sum(nil)

	sig, err := rsa.SignPKCS1v15(rand.Reader, s.cfg.PrivateKey, crypto.SHA256, digest)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrSigningFailed, err)
	}

	encodedSig := base64.RawURLEncoding.EncodeToString(sig)
	return fmt.Sprintf("%s.%s", signingInput, encodedSig), nil
}

func (s *service) GetUserInfo(ctx context.Context, userID string) (map[string]any, error) {
	if userID == "" {
		return nil, ErrUserNotFound
	}

	u, err := s.ctx.Store().Users().GetByID(ctx, userID)
	if err != nil {
		return nil, ErrUserNotFound
	}

	info := map[string]any{
		"sub":            u.ID,
		"email":          u.Email,
		"email_verified": u.EmailVerified,
	}

	return info, nil
}
