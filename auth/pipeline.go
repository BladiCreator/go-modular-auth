package auth

import (
	"github.com/BladiCreator/go-modular-auth/config"
	"github.com/BladiCreator/go-modular-auth/plugin"
)

// Re-exported interceptor interfaces for top-level developer experience.
type (
	SignInInterceptor          = plugin.SignInInterceptor
	SignUpInterceptor          = plugin.SignUpInterceptor
	SessionInterceptor         = plugin.SessionInterceptor
	ValidateSessionInterceptor = plugin.ValidateSessionInterceptor

	BeforeSignInInterceptor          = plugin.BeforeSignInInterceptor
	AfterSignInInterceptor           = plugin.AfterSignInInterceptor
	BeforeSignUpInterceptor          = plugin.BeforeSignUpInterceptor
	AfterSignUpInterceptor           = plugin.AfterSignUpInterceptor
	BeforeCreateSessionInterceptor   = plugin.BeforeCreateSessionInterceptor
	AfterCreateSessionInterceptor    = plugin.AfterCreateSessionInterceptor
	BeforeValidateSessionInterceptor = plugin.BeforeValidateSessionInterceptor
	AfterValidateSessionInterceptor  = plugin.AfterValidateSessionInterceptor

	BeforeSignInFunc          = plugin.BeforeSignInFunc
	AfterSignInFunc           = plugin.AfterSignInFunc
	BeforeSignUpFunc          = plugin.BeforeSignUpFunc
	AfterSignUpFunc           = plugin.AfterSignUpFunc
	BeforeCreateSessionFunc   = plugin.BeforeCreateSessionFunc
	AfterCreateSessionFunc    = plugin.AfterCreateSessionFunc
	BeforeValidateSessionFunc = plugin.BeforeValidateSessionFunc
	AfterValidateSessionFunc  = plugin.AfterValidateSessionFunc

	SignInHandler    = plugin.SignInHandler
	SignInMiddleware = plugin.SignInMiddleware
	SignUpHandler    = plugin.SignUpHandler
	SignUpMiddleware = plugin.SignUpMiddleware

	Pipeline = plugin.Pipeline
)

var (
	// NewPipeline creates a new synchronous execution pipeline.
	NewPipeline = plugin.NewPipeline

	// WithInterceptor registers interceptors globally in engine configuration.
	WithInterceptor = config.WithInterceptor

	// WithBeforeSignIn registers a BeforeSignIn functional interceptor.
	WithBeforeSignIn = config.WithBeforeSignIn

	// WithAfterSignIn registers an AfterSignIn functional interceptor.
	WithAfterSignIn = config.WithAfterSignIn

	// WithBeforeSignUp registers a BeforeSignUp functional interceptor.
	WithBeforeSignUp = config.WithBeforeSignUp

	// WithAfterSignUp registers an AfterSignUp functional interceptor.
	WithAfterSignUp = config.WithAfterSignUp

	// WithBeforeCreateSession registers a BeforeCreateSession functional interceptor.
	WithBeforeCreateSession = config.WithBeforeCreateSession

	// WithAfterCreateSession registers an AfterCreateSession functional interceptor.
	WithAfterCreateSession = config.WithAfterCreateSession

	// WithCallInterceptor attaches an interceptor scoped strictly to an individual call.
	WithCallInterceptor = plugin.WithCallInterceptor
)
