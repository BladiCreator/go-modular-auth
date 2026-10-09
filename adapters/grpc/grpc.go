// Package grpc provides gRPC unary and streaming server interceptors for GoModularAuth.
//
// These interceptors operate outside the core engine, extracting authentication credentials
// from incoming gRPC metadata and propagating the authenticated Principal and Session into
// RPC handlers.
package grpc

import (
	"context"
	"strings"

	auth "github.com/BladiCreator/go-modular-auth"
	"github.com/BladiCreator/go-modular-auth/session"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type contextKey struct{ name string }

var (
	sessionResultKey = contextKey{name: "grpc_session_result"}
)

// MetadataExtractor extracts an authentication token from incoming gRPC metadata.
type MetadataExtractor func(md metadata.MD) string

// BearerMetadataExtractor extracts a Bearer token from the "authorization" metadata key.
func BearerMetadataExtractor(md metadata.MD) string {
	vals := md.Get("authorization")
	if len(vals) == 0 {
		return ""
	}
	for _, val := range vals {
		parts := strings.SplitN(val, " ", 2)
		if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
			return strings.TrimSpace(parts[1])
		}
	}
	return ""
}

// Options configures the gRPC authentication interceptors.
type Options struct {
	Extractor MetadataExtractor
	Lenient   bool
}

// Option modifies Options.
type Option func(*Options)

// WithExtractor sets a custom metadata token extractor.
func WithExtractor(e MetadataExtractor) Option {
	return func(o *Options) {
		if e != nil {
			o.Extractor = e
		}
	}
}

// WithLenient makes the interceptor allow unauthenticated RPCs through without returning an error.
func WithLenient(lenient bool) Option {
	return func(o *Options) {
		o.Lenient = lenient
	}
}

func defaultOptions() Options {
	return Options{
		Extractor: BearerMetadataExtractor,
		Lenient:   false,
	}
}

// UnaryServerInterceptor returns a grpc.UnaryServerInterceptor that validates incoming tokens.
func UnaryServerInterceptor(a *auth.Auth, opts ...Option) grpc.UnaryServerInterceptor {
	cfg := defaultOptions()
	for _, opt := range opts {
		opt(&cfg)
	}

	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		md, _ := metadata.FromIncomingContext(ctx)
		token := cfg.Extractor(md)

		if token == "" {
			if cfg.Lenient {
				return handler(ctx, req)
			}
			return nil, status.Error(codes.Unauthenticated, "missing credentials")
		}

		res, err := a.RequireSession(ctx, token)
		if err != nil || res == nil {
			if cfg.Lenient {
				return handler(ctx, req)
			}
			return nil, status.Error(codes.Unauthenticated, "invalid or expired credentials")
		}

		newCtx := context.WithValue(ctx, sessionResultKey, res)
		newCtx = auth.WithPrincipal(newCtx, res.Principal())

		return handler(newCtx, req)
	}
}

type wrappedServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (w *wrappedServerStream) Context() context.Context {
	return w.ctx
}

// StreamServerInterceptor returns a grpc.StreamServerInterceptor that validates incoming tokens.
func StreamServerInterceptor(a *auth.Auth, opts ...Option) grpc.StreamServerInterceptor {
	cfg := defaultOptions()
	for _, opt := range opts {
		opt(&cfg)
	}

	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		ctx := ss.Context()
		md, _ := metadata.FromIncomingContext(ctx)
		token := cfg.Extractor(md)

		if token == "" {
			if cfg.Lenient {
				return handler(srv, ss)
			}
			return status.Error(codes.Unauthenticated, "missing credentials")
		}

		res, err := a.RequireSession(ctx, token)
		if err != nil || res == nil {
			if cfg.Lenient {
				return handler(srv, ss)
			}
			return status.Error(codes.Unauthenticated, "invalid or expired credentials")
		}

		newCtx := context.WithValue(ctx, sessionResultKey, res)
		newCtx = auth.WithPrincipal(newCtx, res.Principal())

		return handler(srv, &wrappedServerStream{
			ServerStream: ss,
			ctx:          newCtx,
		})
	}
}

// SessionResultFrom returns the SessionResult stored in ctx, if any.
func SessionResultFrom(ctx context.Context) (*auth.SessionResult, bool) {
	res, ok := ctx.Value(sessionResultKey).(*auth.SessionResult)
	return res, ok && res != nil
}

// SessionFrom returns the authenticated session stored in ctx, if any.
func SessionFrom(ctx context.Context) (*session.Session, bool) {
	if res, ok := SessionResultFrom(ctx); ok {
		return res.Session, true
	}
	return nil, false
}

// PrincipalFrom returns the authenticated principal stored in ctx, if any.
func PrincipalFrom(ctx context.Context) (auth.Principal, bool) {
	return auth.PrincipalFrom(ctx)
}
