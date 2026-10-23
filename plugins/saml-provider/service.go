package samlprovider

import (
	"context"
	"encoding/base64"
	"sync"

	sdk "github.com/BladiCreator/go-modular-auth/plugin-sdk"
	"github.com/BladiCreator/go-modular-auth/plugins/saml-provider/metadata"
	"github.com/BladiCreator/go-modular-auth/user"
)

type SAMLProvider interface {
	GetMetadata() ([]byte, error)
	RegisterSP(sp *ServiceProvider) error
	GetSP(entityID string) (*ServiceProvider, error)
	BuildResponse(ctx context.Context, spEntityID string, u *user.User, inResponseTo string) (string, error)
}

type service struct {
	ctx *sdk.Context
	cfg Config

	mu  sync.RWMutex
	sps map[string]*ServiceProvider
}

var _ SAMLProvider = (*service)(nil)

func newService(ctx *sdk.Context, cfg Config) *service {
	return &service{
		ctx: ctx,
		cfg: cfg,
		sps: make(map[string]*ServiceProvider),
	}
}

func (s *service) GetMetadata() ([]byte, error) {
	return metadata.GenerateIdPMetadata(s.cfg.EntityID, s.cfg.SSOURL, s.cfg.Certificate)
}

func (s *service) RegisterSP(sp *ServiceProvider) error {
	if sp == nil || sp.EntityID == "" || sp.ACSURL == "" {
		return ErrInvalidSP
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	cp := *sp
	s.sps[sp.EntityID] = &cp
	return nil
}

func (s *service) GetSP(entityID string) (*ServiceProvider, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	sp, ok := s.sps[entityID]
	if !ok {
		return nil, ErrSPNotFound
	}
	cp := *sp
	return &cp, nil
}

func (s *service) BuildResponse(ctx context.Context, spEntityID string, u *user.User, inResponseTo string) (string, error) {
	if u == nil || u.ID == "" {
		return "", ErrInvalidUser
	}
	if s.cfg.PrivateKey == nil || s.cfg.Certificate == "" {
		return "", ErrKeyNotConfigured
	}

	sp, err := s.GetSP(spEntityID)
	if err != nil {
		return "", err
	}

	xmlStr, err := BuildSAMLResponseXML(
		s.cfg.EntityID,
		sp,
		u,
		inResponseTo,
		s.ctx.Now(),
		s.cfg.PrivateKey,
		s.cfg.Certificate,
	)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString([]byte(xmlStr)), nil
}
