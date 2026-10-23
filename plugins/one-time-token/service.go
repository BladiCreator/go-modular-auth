package ott

import (
	"context"

	auth "github.com/BladiCreator/go-modular-auth"
	sdk "github.com/BladiCreator/go-modular-auth/plugin-sdk"
	"github.com/BladiCreator/go-modular-auth/plugins/one-time-token/events"
	"github.com/BladiCreator/go-modular-auth/verification"
)

type service struct {
	ctx *sdk.Context
	cfg Config
}

var _ OneTimeToken = (*service)(nil)

func newService(ctx *sdk.Context, cfg Config) *service {
	return &service{
		ctx: ctx,
		cfg: cfg,
	}
}

func (s *service) Generate(ctx context.Context, subject string, opts ...GenerateOption) (string, error) {
	if subject == "" {
		return "", ErrInvalidSubject
	}

	opt := GenerateOptions{
		TTL:     s.cfg.DefaultTTL,
		Purpose: s.cfg.Purpose,
	}
	for _, o := range opts {
		o(&opt)
	}

	if opt.TTL <= 0 {
		return "", ErrInvalidTTL
	}

	token, err := s.ctx.Core().IssueToken(ctx, opt.Purpose, subject, opt.TTL)
	if err != nil {
		return "", err
	}

	s.ctx.Events().Publish(ctx, auth.Event{
		Name:    events.EventTokenCreated,
		Time:    s.ctx.Now(),
		Subject: subject,
		Payload: events.TokenCreatedPayload{
			Subject: subject,
			Purpose: string(opt.Purpose),
		},
	})

	return token, nil
}

func (s *service) Consume(ctx context.Context, token string, opts ...GenerateOption) (*verification.Token, error) {
	if token == "" {
		return nil, ErrInvalidToken
	}

	opt := GenerateOptions{
		Purpose: s.cfg.Purpose,
	}
	for _, o := range opts {
		o(&opt)
	}

	vt, err := s.ctx.Core().ConsumeToken(ctx, opt.Purpose, token)
	if err != nil {
		return nil, ErrInvalidToken
	}

	s.ctx.Events().Publish(ctx, auth.Event{
		Name:    events.EventTokenConsumed,
		Time:    s.ctx.Now(),
		Subject: vt.Subject,
		Payload: events.TokenConsumedPayload{
			TokenID: vt.ID,
			Subject: vt.Subject,
			Purpose: string(vt.Purpose),
		},
	})

	return vt, nil
}

func (s *service) Revoke(ctx context.Context, subject string, opts ...GenerateOption) error {
	if subject == "" {
		return ErrInvalidSubject
	}

	opt := GenerateOptions{
		Purpose: s.cfg.Purpose,
	}
	for _, o := range opts {
		o(&opt)
	}

	if err := s.ctx.Core().RevokeTokens(ctx, opt.Purpose, subject); err != nil {
		return err
	}

	s.ctx.Events().Publish(ctx, auth.Event{
		Name:    events.EventTokenRevoked,
		Time:    s.ctx.Now(),
		Subject: subject,
		Payload: events.TokenCreatedPayload{
			Subject: subject,
			Purpose: string(opt.Purpose),
		},
	})

	return nil
}
