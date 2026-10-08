package oauth

import (
	"context"
	"sync"

	"github.com/BladiCreator/go-modular-auth-oauth/provider"
)

// Hooks provides lifecycle interceptors for OAuth authentication flows.
type Hooks struct {
	mu                  sync.RWMutex
	beforeOAuthRedirect []func(ctx context.Context, in *BeginAuthInput) error
	beforeTokenExchange []func(ctx context.Context, providerName string, code string) error
	afterProfileFetched []func(ctx context.Context, profile *provider.ProviderProfile) error
	beforeAccountLink   []func(ctx context.Context, userID string, profile *provider.ProviderProfile) error
	afterOAuthSignIn    []func(ctx context.Context, res *AuthResult) error
}

// NewHooks constructs an empty Hooks registry.
func NewHooks() *Hooks {
	return &Hooks{}
}

// BeforeOAuthRedirect registers an interceptor invoked before building the authorization URL.
func (h *Hooks) BeforeOAuthRedirect(fn func(ctx context.Context, in *BeginAuthInput) error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.beforeOAuthRedirect = append(h.beforeOAuthRedirect, fn)
}

// BeforeTokenExchange registers an interceptor invoked before code exchange with the provider.
func (h *Hooks) BeforeTokenExchange(fn func(ctx context.Context, providerName string, code string) error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.beforeTokenExchange = append(h.beforeTokenExchange, fn)
}

// AfterProfileFetched registers an interceptor invoked immediately after user profile claims are parsed.
func (h *Hooks) AfterProfileFetched(fn func(ctx context.Context, profile *provider.ProviderProfile) error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.afterProfileFetched = append(h.afterProfileFetched, fn)
}

// BeforeAccountLink registers an interceptor invoked before linking a provider account to a user.
func (h *Hooks) BeforeAccountLink(fn func(ctx context.Context, userID string, profile *provider.ProviderProfile) error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.beforeAccountLink = append(h.beforeAccountLink, fn)
}

// AfterOAuthSignIn registers an interceptor invoked after session creation on successful sign-in.
func (h *Hooks) AfterOAuthSignIn(fn func(ctx context.Context, res *AuthResult) error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.afterOAuthSignIn = append(h.afterOAuthSignIn, fn)
}

func (h *Hooks) runBeforeOAuthRedirect(ctx context.Context, in *BeginAuthInput) error {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, fn := range h.beforeOAuthRedirect {
		if err := fn(ctx, in); err != nil {
			return err
		}
	}
	return nil
}

func (h *Hooks) runBeforeTokenExchange(ctx context.Context, providerName, code string) error {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, fn := range h.beforeTokenExchange {
		if err := fn(ctx, providerName, code); err != nil {
			return err
		}
	}
	return nil
}

func (h *Hooks) runAfterProfileFetched(ctx context.Context, profile *provider.ProviderProfile) error {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, fn := range h.afterProfileFetched {
		if err := fn(ctx, profile); err != nil {
			return err
		}
	}
	return nil
}

func (h *Hooks) runBeforeAccountLink(ctx context.Context, userID string, profile *provider.ProviderProfile) error {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, fn := range h.beforeAccountLink {
		if err := fn(ctx, userID, profile); err != nil {
			return err
		}
	}
	return nil
}

func (h *Hooks) runAfterOAuthSignIn(ctx context.Context, res *AuthResult) error {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, fn := range h.afterOAuthSignIn {
		if err := fn(ctx, res); err != nil {
			return err
		}
	}
	return nil
}
