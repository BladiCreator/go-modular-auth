package auth

import (
	"context"
	"sync"

	"github.com/BladiCreator/go-modular-auth/session"
	"github.com/BladiCreator/go-modular-auth/user"
)

// Hooks let applications and plugins intervene in core workflows.
//
// Hooks differ from Events: a Before hook may mutate its input or abort the
// workflow by returning an error (returned unchanged to the caller); an After
// hook runs once the Store transaction has committed and observes the result.
//
// BeforeUserCreate and BeforeSessionCreate run INSIDE the Store transaction:
// store operations performed with the received ctx join that transaction, so
// plugins can atomically persist their own rows (or veto the operation).
type Hooks struct {
	beforeSignUp        chain[SignUpInput]
	afterSignUp         observers[AuthResult]
	beforeSignIn        chain[SignInInput]
	afterSignIn         observers[AuthResult]
	beforeSignOut       chain[SignOutInput]
	afterSignOut        observers[session.Session]
	beforeUserCreate    chain[user.User]
	afterUserCreate     observers[user.User]
	beforeSessionCreate chain[session.Session]
}

// BeforeSignUp registers a hook run before input validation.
func (h *Hooks) BeforeSignUp(fn func(ctx context.Context, in *SignUpInput) error) {
	h.beforeSignUp.add(fn)
}

// AfterSignUp registers a hook run after a successful sign up.
func (h *Hooks) AfterSignUp(fn func(ctx context.Context, res *AuthResult)) { h.afterSignUp.add(fn) }

// BeforeSignIn registers a hook run before credentials are checked
// (e.g. rate limiting, captcha).
func (h *Hooks) BeforeSignIn(fn func(ctx context.Context, in *SignInInput) error) {
	h.beforeSignIn.add(fn)
}

// AfterSignIn registers a hook run after a successful sign in.
func (h *Hooks) AfterSignIn(fn func(ctx context.Context, res *AuthResult)) { h.afterSignIn.add(fn) }

// BeforeSignOut registers a hook run before a session is revoked.
func (h *Hooks) BeforeSignOut(fn func(ctx context.Context, in *SignOutInput) error) {
	h.beforeSignOut.add(fn)
}

// AfterSignOut registers a hook run after a session has been revoked.
func (h *Hooks) AfterSignOut(fn func(ctx context.Context, s *session.Session)) {
	h.afterSignOut.add(fn)
}

// BeforeUserCreate registers a hook run inside the transaction before a user is persisted.
func (h *Hooks) BeforeUserCreate(fn func(ctx context.Context, u *user.User) error) {
	h.beforeUserCreate.add(fn)
}

// AfterUserCreate registers a hook run after the user creation has committed.
func (h *Hooks) AfterUserCreate(fn func(ctx context.Context, u *user.User)) {
	h.afterUserCreate.add(fn)
}

// BeforeSessionCreate registers a hook run inside the transaction before a
// session is persisted (e.g. enforce a maximum number of sessions).
func (h *Hooks) BeforeSessionCreate(fn func(ctx context.Context, s *session.Session) error) {
	h.beforeSessionCreate.add(fn)
}

type chain[T any] struct {
	mu  sync.RWMutex
	fns []func(context.Context, *T) error
}

func (c *chain[T]) add(fn func(context.Context, *T) error) {
	c.mu.Lock()
	c.fns = append(c.fns, fn)
	c.mu.Unlock()
}

func (c *chain[T]) run(ctx context.Context, v *T) error {
	c.mu.RLock()
	fns := c.fns
	c.mu.RUnlock()
	for _, fn := range fns {
		if err := fn(ctx, v); err != nil {
			return err
		}
	}
	return nil
}

type observers[T any] struct {
	mu  sync.RWMutex
	fns []func(context.Context, *T)
}

func (o *observers[T]) add(fn func(context.Context, *T)) {
	o.mu.Lock()
	o.fns = append(o.fns, fn)
	o.mu.Unlock()
}

func (o *observers[T]) run(ctx context.Context, v *T) {
	o.mu.RLock()
	fns := o.fns
	o.mu.RUnlock()
	for _, fn := range fns {
		fn(ctx, v)
	}
}
