package grpc_test

import (
	"context"
	"testing"
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	grpcadapter "github.com/BladiCreator/go-modular-auth/adapters/grpc"
	storememory "github.com/BladiCreator/go-modular-auth/store/memory"
	"github.com/BladiCreator/go-modular-auth/user"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func setupAuth(t *testing.T) (*auth.Auth, string, string) {
	t.Helper()
	s := storememory.New()
	a, err := auth.New(auth.Config{Store: s})
	if err != nil {
		t.Fatalf("failed to init auth: %v", err)
	}

	ctx := context.Background()
	u := &user.User{
		ID:        "user-grpc-1",
		Email:     "grpc@example.com",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := s.Users().Create(ctx, u); err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	issued, err := a.CreateSession(ctx, u.ID, auth.SessionOptions{})
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	return a, u.ID, issued.Token
}

func TestGRPCAdapter_UnaryInterceptor(t *testing.T) {
	a, expectedUserID, rawToken := setupAuth(t)
	interceptor := grpcadapter.UnaryServerInterceptor(a)

	dummyHandler := func(ctx context.Context, req any) (any, error) {
		p, ok := grpcadapter.PrincipalFrom(ctx)
		if !ok {
			return nil, status.Error(codes.Internal, "no principal")
		}
		return p.Subject, nil
	}

	info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/TestMethod"}

	// 1. Missing metadata -> Unauthenticated
	ctx := context.Background()
	_, err := interceptor(ctx, nil, info, dummyHandler)
	if status.Code(err) != codes.Unauthenticated {
		t.Errorf("expected Unauthenticated, got: %v", err)
	}

	// 2. Invalid token -> Unauthenticated
	ctxWithInvalid := metadata.NewIncomingContext(ctx, metadata.Pairs("authorization", "Bearer bad-token"))
	_, err = interceptor(ctxWithInvalid, nil, info, dummyHandler)
	if status.Code(err) != codes.Unauthenticated {
		t.Errorf("expected Unauthenticated on bad token, got: %v", err)
	}

	// 3. Valid token -> Success and principal in context
	ctxWithValid := metadata.NewIncomingContext(ctx, metadata.Pairs("authorization", "Bearer "+rawToken))
	resp, err := interceptor(ctxWithValid, nil, info, dummyHandler)
	if err != nil {
		t.Fatalf("expected success, got: %v", err)
	}
	if resp.(string) != expectedUserID {
		t.Errorf("expected subject %s, got: %v", expectedUserID, resp)
	}
}

type mockServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (m *mockServerStream) Context() context.Context {
	return m.ctx
}

func TestGRPCAdapter_StreamInterceptor(t *testing.T) {
	a, expectedUserID, rawToken := setupAuth(t)
	interceptor := grpcadapter.StreamServerInterceptor(a)

	streamHandler := func(srv any, ss grpc.ServerStream) error {
		p, ok := grpcadapter.PrincipalFrom(ss.Context())
		if !ok || p.Subject != expectedUserID {
			return status.Error(codes.Internal, "principal mismatch")
		}
		return nil
	}

	info := &grpc.StreamServerInfo{FullMethod: "/test.Service/StreamMethod"}

	// Valid token stream
	incomingCtx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+rawToken))
	mockStream := &mockServerStream{ctx: incomingCtx}

	if err := interceptor(nil, mockStream, info, streamHandler); err != nil {
		t.Fatalf("expected stream success, got: %v", err)
	}
}
