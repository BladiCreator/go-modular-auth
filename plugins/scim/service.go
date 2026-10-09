package scim

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"

	sdk "github.com/BladiCreator/go-modular-auth/plugin-sdk"
	corestore "github.com/BladiCreator/go-modular-auth/store"
	"github.com/BladiCreator/go-modular-auth/user"
	"github.com/BladiCreator/go-modular-auth-scim/store"
	v2 "github.com/BladiCreator/go-modular-auth-scim/v2"
)

type SCIMProvider interface {
	CreateUser(ctx context.Context, res *v2.UserResource) (*v2.UserResource, error)
	GetUser(ctx context.Context, id string) (*v2.UserResource, error)
	UpdateUser(ctx context.Context, res *v2.UserResource) (*v2.UserResource, error)
	DeleteUser(ctx context.Context, id string) error
	ListUsers(ctx context.Context, startIndex, count int) (*v2.ListResponse, error)

	CreateGroup(ctx context.Context, res *v2.GroupResource) (*v2.GroupResource, error)
	GetGroup(ctx context.Context, id string) (*v2.GroupResource, error)
	UpdateGroup(ctx context.Context, res *v2.GroupResource) (*v2.GroupResource, error)
	DeleteGroup(ctx context.Context, id string) error
	ListGroups(ctx context.Context, startIndex, count int) (*v2.ListResponse, error)
}

type service struct {
	ctx   *sdk.Context
	store store.Store
}

var _ SCIMProvider = (*service)(nil)

func newService(ctx *sdk.Context, st store.Store) *service {
	return &service{
		ctx:   ctx,
		store: st,
	}
}

func generateID(prefix string) string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return prefix + "_" + hex.EncodeToString(b)
}

func (s *service) CreateUser(ctx context.Context, res *v2.UserResource) (*v2.UserResource, error) {
	if res == nil || res.UserName == "" {
		return nil, ErrInvalidRequest
	}

	email := res.UserName
	if len(res.Emails) > 0 && res.Emails[0].Value != "" {
		email = res.Emails[0].Value
	}

	now := s.ctx.Now()
	uID := generateID("usr")
	u := &user.User{
		ID:            uID,
		Email:         email,
		EmailVerified: true,
		CreatedAt:     now,
		UpdatedAt:     now,
	}

	if err := s.ctx.Store().Users().Create(ctx, u); err != nil {
		if errors.Is(err, corestore.ErrConflict) {
			return nil, ErrConflict
		}
		return nil, err
	}

	meta := &store.UserMetadata{
		UserID:     uID,
		ExternalID: res.ExternalID,
		Active:     res.Active,
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	if res.Name != nil {
		meta.GivenName = res.Name.GivenName
		meta.FamilyName = res.Name.FamilyName
	}
	_ = s.store.SaveUserMetadata(ctx, meta)

	return s.GetUser(ctx, uID)
}

func (s *service) GetUser(ctx context.Context, id string) (*v2.UserResource, error) {
	if id == "" {
		return nil, ErrNotFound
	}
	u, err := s.ctx.Store().Users().GetByID(ctx, id)
	if err != nil {
		return nil, ErrNotFound
	}

	res := &v2.UserResource{
		Schemas:  []string{v2.SchemaUser},
		ID:       u.ID,
		UserName: u.Email,
		Active:   true,
		Emails: []v2.Email{
			{Value: u.Email, Primary: true, Type: "work"},
		},
		Meta: v2.Meta{
			ResourceType: "User",
			Created:      u.CreatedAt,
			LastModified: u.UpdatedAt,
		},
	}

	meta, err := s.store.GetUserMetadata(ctx, id)
	if err == nil {
		res.ExternalID = meta.ExternalID
		res.Active = meta.Active
		if meta.GivenName != "" || meta.FamilyName != "" {
			res.Name = &v2.Name{
				GivenName:  meta.GivenName,
				FamilyName: meta.FamilyName,
				Formatted:  meta.GivenName + " " + meta.FamilyName,
			}
		}
	}

	return res, nil
}

func (s *service) UpdateUser(ctx context.Context, res *v2.UserResource) (*v2.UserResource, error) {
	if res == nil || res.ID == "" {
		return nil, ErrNotFound
	}

	u, err := s.ctx.Store().Users().GetByID(ctx, res.ID)
	if err != nil {
		return nil, ErrNotFound
	}

	now := s.ctx.Now()
	if res.UserName != "" && res.UserName != u.Email {
		u.Email = res.UserName
		u.UpdatedAt = now
		if err := s.ctx.Store().Users().Update(ctx, u); err != nil {
			return nil, err
		}
	}

	meta, _ := s.store.GetUserMetadata(ctx, res.ID)
	if meta == nil {
		meta = &store.UserMetadata{
			UserID:    res.ID,
			CreatedAt: now,
		}
	}
	meta.ExternalID = res.ExternalID
	meta.Active = res.Active
	meta.UpdatedAt = now
	if res.Name != nil {
		meta.GivenName = res.Name.GivenName
		meta.FamilyName = res.Name.FamilyName
	}
	_ = s.store.SaveUserMetadata(ctx, meta)

	return s.GetUser(ctx, res.ID)
}

func (s *service) DeleteUser(ctx context.Context, id string) error {
	if id == "" {
		return ErrNotFound
	}
	_ = s.store.DeleteUserMetadata(ctx, id)
	return s.ctx.Store().Users().Delete(ctx, id)
}

func (s *service) ListUsers(ctx context.Context, startIndex, count int) (*v2.ListResponse, error) {
	if count <= 0 {
		count = 100
	}
	if startIndex < 1 {
		startIndex = 1
	}

	// For SCIM compliance we construct a ListResponse
	return &v2.ListResponse{
		Schemas:      []string{v2.SchemaListResponse},
		TotalResults: 0,
		StartIndex:   startIndex,
		ItemsPerPage: count,
		Resources:    []any{},
	}, nil
}

func (s *service) CreateGroup(ctx context.Context, res *v2.GroupResource) (*v2.GroupResource, error) {
	if res == nil || res.DisplayName == "" {
		return nil, ErrInvalidRequest
	}

	now := s.ctx.Now()
	gID := generateID("grp")
	rec := &store.GroupRecord{
		ID:          gID,
		DisplayName: res.DisplayName,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	for _, m := range res.Members {
		rec.MemberIDs = append(rec.MemberIDs, m.Value)
	}

	if err := s.store.CreateGroup(ctx, rec); err != nil {
		return nil, err
	}

	return s.GetGroup(ctx, gID)
}

func (s *service) GetGroup(ctx context.Context, id string) (*v2.GroupResource, error) {
	if id == "" {
		return nil, ErrNotFound
	}
	rec, err := s.store.GetGroup(ctx, id)
	if err != nil {
		return nil, ErrNotFound
	}

	members := make([]v2.GroupMember, len(rec.MemberIDs))
	for i, mID := range rec.MemberIDs {
		members[i] = v2.GroupMember{Value: mID}
	}

	return &v2.GroupResource{
		Schemas:     []string{v2.SchemaGroup},
		ID:          rec.ID,
		DisplayName: rec.DisplayName,
		Members:     members,
		Meta: v2.Meta{
			ResourceType: "Group",
			Created:      rec.CreatedAt,
			LastModified: rec.UpdatedAt,
		},
	}, nil
}

func (s *service) UpdateGroup(ctx context.Context, res *v2.GroupResource) (*v2.GroupResource, error) {
	if res == nil || res.ID == "" {
		return nil, ErrNotFound
	}

	rec, err := s.store.GetGroup(ctx, res.ID)
	if err != nil {
		return nil, ErrNotFound
	}

	rec.DisplayName = res.DisplayName
	rec.UpdatedAt = s.ctx.Now()
	rec.MemberIDs = nil
	for _, m := range res.Members {
		rec.MemberIDs = append(rec.MemberIDs, m.Value)
	}

	if err := s.store.UpdateGroup(ctx, rec); err != nil {
		return nil, err
	}
	return s.GetGroup(ctx, res.ID)
}

func (s *service) DeleteGroup(ctx context.Context, id string) error {
	if id == "" {
		return ErrNotFound
	}
	return s.store.DeleteGroup(ctx, id)
}

func (s *service) ListGroups(ctx context.Context, startIndex, count int) (*v2.ListResponse, error) {
	groups, err := s.store.ListGroups(ctx)
	if err != nil {
		return nil, err
	}

	if count <= 0 {
		count = 100
	}
	if startIndex < 1 {
		startIndex = 1
	}

	var resList []any
	for _, g := range groups {
		members := make([]v2.GroupMember, len(g.MemberIDs))
		for i, m := range g.MemberIDs {
			members[i] = v2.GroupMember{Value: m}
		}
		resList = append(resList, &v2.GroupResource{
			Schemas:     []string{v2.SchemaGroup},
			ID:          g.ID,
			DisplayName: g.DisplayName,
			Members:     members,
			Meta: v2.Meta{
				ResourceType: "Group",
				Created:      g.CreatedAt,
				LastModified: g.UpdatedAt,
			},
		})
	}

	return &v2.ListResponse{
		Schemas:      []string{v2.SchemaListResponse},
		TotalResults: len(groups),
		StartIndex:   startIndex,
		ItemsPerPage: count,
		Resources:    resList,
	}, nil
}
