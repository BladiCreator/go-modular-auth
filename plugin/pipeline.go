package plugin

import (
	"context"
	"sync"

	"github.com/BladiCreator/go-modular-auth/domain/dto"
	"github.com/BladiCreator/go-modular-auth/domain/entity"
)

// SignInInterceptor intercepts the user sign-in authentication flow.
type SignInInterceptor interface {
	BeforeSignIn(ctx context.Context, input *dto.SignInParams) error
	AfterSignIn(ctx context.Context, data *dto.SessionData) error
}

// SignUpInterceptor intercepts the user registration sign-up flow.
type SignUpInterceptor interface {
	BeforeSignUp(ctx context.Context, input *dto.SignUpParams) error
	AfterSignUp(ctx context.Context, user *entity.User) error
}

// SessionInterceptor intercepts session creation and lifecycle operations in SessionManager.
type SessionInterceptor interface {
	BeforeCreateSession(ctx context.Context, params *dto.CreateSessionParams) error
	AfterCreateSession(ctx context.Context, session *entity.Session) error
}

// ValidateSessionInterceptor intercepts session validation operations.
type ValidateSessionInterceptor interface {
	BeforeValidateSession(ctx context.Context, token string) error
	AfterValidateSession(ctx context.Context, data *dto.SessionData) error
}

// Single-method interface contracts for maximum flexibility and duck typing.
type (
	BeforeSignInInterceptor interface {
		BeforeSignIn(ctx context.Context, input *dto.SignInParams) error
	}
	AfterSignInInterceptor interface {
		AfterSignIn(ctx context.Context, data *dto.SessionData) error
	}
	BeforeSignUpInterceptor interface {
		BeforeSignUp(ctx context.Context, input *dto.SignUpParams) error
	}
	AfterSignUpInterceptor interface {
		AfterSignUp(ctx context.Context, user *entity.User) error
	}
	BeforeCreateSessionInterceptor interface {
		BeforeCreateSession(ctx context.Context, params *dto.CreateSessionParams) error
	}
	AfterCreateSessionInterceptor interface {
		AfterCreateSession(ctx context.Context, session *entity.Session) error
	}
	BeforeValidateSessionInterceptor interface {
		BeforeValidateSession(ctx context.Context, token string) error
	}
	AfterValidateSessionInterceptor interface {
		AfterValidateSession(ctx context.Context, data *dto.SessionData) error
	}
)

// Functional adapters allowing plain functions to satisfy interceptor interfaces.
type (
	BeforeSignInFunc          func(ctx context.Context, input *dto.SignInParams) error
	AfterSignInFunc           func(ctx context.Context, data *dto.SessionData) error
	BeforeSignUpFunc          func(ctx context.Context, input *dto.SignUpParams) error
	AfterSignUpFunc           func(ctx context.Context, user *entity.User) error
	BeforeCreateSessionFunc   func(ctx context.Context, params *dto.CreateSessionParams) error
	AfterCreateSessionFunc    func(ctx context.Context, session *entity.Session) error
	BeforeValidateSessionFunc func(ctx context.Context, token string) error
	AfterValidateSessionFunc  func(ctx context.Context, data *dto.SessionData) error
)

func (f BeforeSignInFunc) BeforeSignIn(ctx context.Context, input *dto.SignInParams) error {
	return f(ctx, input)
}
func (f AfterSignInFunc) AfterSignIn(ctx context.Context, data *dto.SessionData) error {
	return f(ctx, data)
}
func (f BeforeSignUpFunc) BeforeSignUp(ctx context.Context, input *dto.SignUpParams) error {
	return f(ctx, input)
}
func (f AfterSignUpFunc) AfterSignUp(ctx context.Context, user *entity.User) error {
	return f(ctx, user)
}
func (f BeforeCreateSessionFunc) BeforeCreateSession(ctx context.Context, params *dto.CreateSessionParams) error {
	return f(ctx, params)
}
func (f AfterCreateSessionFunc) AfterCreateSession(ctx context.Context, session *entity.Session) error {
	return f(ctx, session)
}
func (f BeforeValidateSessionFunc) BeforeValidateSession(ctx context.Context, token string) error {
	return f(ctx, token)
}
func (f AfterValidateSessionFunc) AfterValidateSession(ctx context.Context, data *dto.SessionData) error {
	return f(ctx, data)
}

// Onion middleware signatures for developers preferring middleware chaining.
type (
	SignInHandler    func(ctx context.Context, input *dto.SignInParams) (*dto.SessionData, error)
	SignInMiddleware func(next SignInHandler) SignInHandler

	SignUpHandler    func(ctx context.Context, input *dto.SignUpParams) (*entity.User, error)
	SignUpMiddleware func(next SignUpHandler) SignUpHandler
)

// Pipeline manages sequential interceptors and middlewares for authentication operations.
type Pipeline struct {
	mu                    sync.RWMutex
	beforeSignIn          []BeforeSignInInterceptor
	afterSignIn           []AfterSignInInterceptor
	beforeSignUp          []BeforeSignUpInterceptor
	afterSignUp           []AfterSignUpInterceptor
	beforeCreateSession   []BeforeCreateSessionInterceptor
	afterCreateSession    []AfterCreateSessionInterceptor
	beforeValidateSession []BeforeValidateSessionInterceptor
	afterValidateSession  []AfterValidateSessionInterceptor
	signInMiddlewares     []SignInMiddleware
	signUpMiddlewares     []SignUpMiddleware
}

// NewPipeline initializes a new empty Pipeline.
func NewPipeline() *Pipeline {
	return &Pipeline{}
}

// AddInterceptor inspects and registers any supported interceptor implementation.
func (p *Pipeline) AddInterceptor(interceptors ...any) *Pipeline {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, it := range interceptors {
		if it == nil {
			continue
		}

		if bsi, ok := it.(BeforeSignInInterceptor); ok {
			p.beforeSignIn = append(p.beforeSignIn, bsi)
		}
		if asi, ok := it.(AfterSignInInterceptor); ok {
			p.afterSignIn = append(p.afterSignIn, asi)
		}
		if bsu, ok := it.(BeforeSignUpInterceptor); ok {
			p.beforeSignUp = append(p.beforeSignUp, bsu)
		}
		if asu, ok := it.(AfterSignUpInterceptor); ok {
			p.afterSignUp = append(p.afterSignUp, asu)
		}
		if bcs, ok := it.(BeforeCreateSessionInterceptor); ok {
			p.beforeCreateSession = append(p.beforeCreateSession, bcs)
		}
		if acs, ok := it.(AfterCreateSessionInterceptor); ok {
			p.afterCreateSession = append(p.afterCreateSession, acs)
		}
		if bvs, ok := it.(BeforeValidateSessionInterceptor); ok {
			p.beforeValidateSession = append(p.beforeValidateSession, bvs)
		}
		if avs, ok := it.(AfterValidateSessionInterceptor); ok {
			p.afterValidateSession = append(p.afterValidateSession, avs)
		}
	}
	return p
}

// BeforeSignIn registers functional interceptors executed before user sign-in.
func (p *Pipeline) BeforeSignIn(fns ...BeforeSignInFunc) *Pipeline {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, fn := range fns {
		if fn != nil {
			p.beforeSignIn = append(p.beforeSignIn, fn)
		}
	}
	return p
}

// AfterSignIn registers functional interceptors executed after successful user sign-in.
func (p *Pipeline) AfterSignIn(fns ...AfterSignInFunc) *Pipeline {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, fn := range fns {
		if fn != nil {
			p.afterSignIn = append(p.afterSignIn, fn)
		}
	}
	return p
}

// BeforeSignUp registers functional interceptors executed before user registration.
func (p *Pipeline) BeforeSignUp(fns ...BeforeSignUpFunc) *Pipeline {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, fn := range fns {
		if fn != nil {
			p.beforeSignUp = append(p.beforeSignUp, fn)
		}
	}
	return p
}

// AfterSignUp registers functional interceptors executed after user registration.
func (p *Pipeline) AfterSignUp(fns ...AfterSignUpFunc) *Pipeline {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, fn := range fns {
		if fn != nil {
			p.afterSignUp = append(p.afterSignUp, fn)
		}
	}
	return p
}

// BeforeCreateSession registers functional interceptors executed before session persistence.
func (p *Pipeline) BeforeCreateSession(fns ...BeforeCreateSessionFunc) *Pipeline {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, fn := range fns {
		if fn != nil {
			p.beforeCreateSession = append(p.beforeCreateSession, fn)
		}
	}
	return p
}

// AfterCreateSession registers functional interceptors executed after session persistence.
func (p *Pipeline) AfterCreateSession(fns ...AfterCreateSessionFunc) *Pipeline {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, fn := range fns {
		if fn != nil {
			p.afterCreateSession = append(p.afterCreateSession, fn)
		}
	}
	return p
}

// UseSignInMiddleware registers onion middlewares wrapping the complete sign-in execution.
func (p *Pipeline) UseSignInMiddleware(mws ...SignInMiddleware) *Pipeline {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.signInMiddlewares = append(p.signInMiddlewares, mws...)
	return p
}

// UseSignUpMiddleware registers onion middlewares wrapping the complete sign-up execution.
func (p *Pipeline) UseSignUpMiddleware(mws ...SignUpMiddleware) *Pipeline {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.signUpMiddlewares = append(p.signUpMiddlewares, mws...)
	return p
}

// ExecuteBeforeSignIn runs registered BeforeSignIn interceptors sequentially, aborting immediately on error.
func (p *Pipeline) ExecuteBeforeSignIn(ctx context.Context, input *dto.SignInParams, extraInterceptors ...any) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if p != nil {
		p.mu.RLock()
		for _, it := range p.beforeSignIn {
			if err := it.BeforeSignIn(ctx, input); err != nil {
				p.mu.RUnlock()
				return err
			}
		}
		p.mu.RUnlock()
	}
	for _, extra := range extraInterceptors {
		if bsi, ok := extra.(BeforeSignInInterceptor); ok && bsi != nil {
			if err := bsi.BeforeSignIn(ctx, input); err != nil {
				return err
			}
		}
	}
	return nil
}

// ExecuteAfterSignIn runs registered AfterSignIn interceptors sequentially, aborting immediately on error.
func (p *Pipeline) ExecuteAfterSignIn(ctx context.Context, data *dto.SessionData, extraInterceptors ...any) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if p != nil {
		p.mu.RLock()
		for _, it := range p.afterSignIn {
			if err := it.AfterSignIn(ctx, data); err != nil {
				p.mu.RUnlock()
				return err
			}
		}
		p.mu.RUnlock()
	}
	for _, extra := range extraInterceptors {
		if asi, ok := extra.(AfterSignInInterceptor); ok && asi != nil {
			if err := asi.AfterSignIn(ctx, data); err != nil {
				return err
			}
		}
	}
	return nil
}

// ExecuteBeforeSignUp runs registered BeforeSignUp interceptors sequentially, aborting immediately on error.
func (p *Pipeline) ExecuteBeforeSignUp(ctx context.Context, input *dto.SignUpParams, extraInterceptors ...any) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if p != nil {
		p.mu.RLock()
		for _, it := range p.beforeSignUp {
			if err := it.BeforeSignUp(ctx, input); err != nil {
				p.mu.RUnlock()
				return err
			}
		}
		p.mu.RUnlock()
	}
	for _, extra := range extraInterceptors {
		if bsu, ok := extra.(BeforeSignUpInterceptor); ok && bsu != nil {
			if err := bsu.BeforeSignUp(ctx, input); err != nil {
				return err
			}
		}
	}
	return nil
}

// ExecuteAfterSignUp runs registered AfterSignUp interceptors sequentially, aborting immediately on error.
func (p *Pipeline) ExecuteAfterSignUp(ctx context.Context, user *entity.User, extraInterceptors ...any) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if p != nil {
		p.mu.RLock()
		for _, it := range p.afterSignUp {
			if err := it.AfterSignUp(ctx, user); err != nil {
				p.mu.RUnlock()
				return err
			}
		}
		p.mu.RUnlock()
	}
	for _, extra := range extraInterceptors {
		if asu, ok := extra.(AfterSignUpInterceptor); ok && asu != nil {
			if err := asu.AfterSignUp(ctx, user); err != nil {
				return err
			}
		}
	}
	return nil
}

// ExecuteBeforeCreateSession runs registered BeforeCreateSession interceptors sequentially, aborting immediately on error.
func (p *Pipeline) ExecuteBeforeCreateSession(ctx context.Context, params *dto.CreateSessionParams, extraInterceptors ...any) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if p != nil {
		p.mu.RLock()
		for _, it := range p.beforeCreateSession {
			if err := it.BeforeCreateSession(ctx, params); err != nil {
				p.mu.RUnlock()
				return err
			}
		}
		p.mu.RUnlock()
	}
	for _, extra := range extraInterceptors {
		if bcs, ok := extra.(BeforeCreateSessionInterceptor); ok && bcs != nil {
			if err := bcs.BeforeCreateSession(ctx, params); err != nil {
				return err
			}
		}
	}
	return nil
}

// ExecuteAfterCreateSession runs registered AfterCreateSession interceptors sequentially, aborting immediately on error.
func (p *Pipeline) ExecuteAfterCreateSession(ctx context.Context, session *entity.Session, extraInterceptors ...any) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if p != nil {
		p.mu.RLock()
		for _, it := range p.afterCreateSession {
			if err := it.AfterCreateSession(ctx, session); err != nil {
				p.mu.RUnlock()
				return err
			}
		}
		p.mu.RUnlock()
	}
	for _, extra := range extraInterceptors {
		if acs, ok := extra.(AfterCreateSessionInterceptor); ok && acs != nil {
			if err := acs.AfterCreateSession(ctx, session); err != nil {
				return err
			}
		}
	}
	return nil
}

// ExecuteBeforeValidateSession runs registered BeforeValidateSession interceptors sequentially.
func (p *Pipeline) ExecuteBeforeValidateSession(ctx context.Context, token string, extraInterceptors ...any) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if p != nil {
		p.mu.RLock()
		for _, it := range p.beforeValidateSession {
			if err := it.BeforeValidateSession(ctx, token); err != nil {
				p.mu.RUnlock()
				return err
			}
		}
		p.mu.RUnlock()
	}
	for _, extra := range extraInterceptors {
		if bvs, ok := extra.(BeforeValidateSessionInterceptor); ok && bvs != nil {
			if err := bvs.BeforeValidateSession(ctx, token); err != nil {
				return err
			}
		}
	}
	return nil
}

// ExecuteAfterValidateSession runs registered AfterValidateSession interceptors sequentially.
func (p *Pipeline) ExecuteAfterValidateSession(ctx context.Context, data *dto.SessionData, extraInterceptors ...any) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if p != nil {
		p.mu.RLock()
		for _, it := range p.afterValidateSession {
			if err := it.AfterValidateSession(ctx, data); err != nil {
				p.mu.RUnlock()
				return err
			}
		}
		p.mu.RUnlock()
	}
	for _, extra := range extraInterceptors {
		if avs, ok := extra.(AfterValidateSessionInterceptor); ok && avs != nil {
			if err := avs.AfterValidateSession(ctx, data); err != nil {
				return err
			}
		}
	}
	return nil
}
