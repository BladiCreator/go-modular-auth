package scim

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"

	"github.com/BladiCreator/go-modular-auth/adapter"
	sdk "github.com/BladiCreator/go-modular-auth/plugin-sdk"
	corestore "github.com/BladiCreator/go-modular-auth/store"
	"github.com/BladiCreator/go-modular-auth/user"
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
	ctx      *sdk.Context
	userMeta *sdk.Repository[UserMetadata]
	groups   *sdk.Repository[GroupRecord]
}

var _ SCIMProvider = (*service)(nil)

func newService(ctx *sdk.Context) *service {
	return &service{
		ctx:      ctx,
		userMeta: sdk.Model[UserMetadata](ctx, ModelSCIMUserMetadata),
		groups:   sdk.Model[GroupRecord](ctx, ModelSCIMGroups),
	}
}

func generateID(prefix string) string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return prefix + "_" + hex.EncodeToString(b)
}

func (s *service) now() time.Time {
	if s.ctx != nil {
		return s.ctx.Now()
	}
	return time.Now()
}

func (s *service) saveUserMetadata(ctx context.Context, meta *UserMetadata) error {
	existing, _ := s.userMeta.FindOne(ctx, adapter.Eq("user_id", meta.UserID))
	if existing == nil {
		return s.userMeta.Create(ctx, meta)
	}
	_, err := s.userMeta.Update(ctx, []adapter.Condition{adapter.Eq("user_id", meta.UserID)}, map[string]any{
		"external_id": meta.ExternalID,
		"active":      meta.Active,
		"given_name":  meta.GivenName,
		"family_name": meta.FamilyName,
		"updated_at":  meta.UpdatedAt,
	})
	return err
}

func (s *service) CreateUser(ctx context.Context, res *v2.UserResource) (*v2.UserResource, error) {
	if res == nil || res.UserName == "" {
		return nil, ErrInvalidRequest
	}

	email := res.UserName
	if len(res.Emails) > 0 && res.Emails[0].Value != "" {
		email = res.Emails[0].Value
	}

	now := s.now()
	uID := generateID("usr")
	u := &user.User{
		ID:            uID,
		Email:         email,
		EmailVerified: true,
		CreatedAt:     now,
		UpdatedAt:     now,
	}

	if s.ctx != nil && s.ctx.Store() != nil && s.ctx.Store().Users() != nil {
		if err := s.ctx.Store().Users().Create(ctx, u); err != nil {
			if errors.Is(err, corestore.ErrConflict) {
				return nil, ErrConflict
			}
			return nil, err
		}
	}

	meta := &UserMetadata{
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
	_ = s.saveUserMetadata(ctx, meta)

	return s.GetUser(ctx, uID)
}

func (s *service) GetUser(ctx context.Context, id string) (*v2.UserResource, error) {
	if id == "" {
		return nil, ErrNotFound
	}

	var u *user.User
	var err error
	if s.ctx != nil && s.ctx.Store() != nil && s.ctx.Store().Users() != nil {
		u, err = s.ctx.Store().Users().GetByID(ctx, id)
	}
	if err != nil || u == nil {
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

	meta, err := s.userMeta.FindOne(ctx, adapter.Eq("user_id", id))
	if err == nil && meta != nil {
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

	if s.ctx == nil || s.ctx.Store() == nil || s.ctx.Store().Users() == nil {
		return nil, ErrNotFound
	}

	u, err := s.ctx.Store().Users().GetByID(ctx, res.ID)
	if err != nil || u == nil {
		return nil, ErrNotFound
	}

	now := s.now()
	if res.UserName != "" && res.UserName != u.Email {
		u.Email = res.UserName
		u.UpdatedAt = now
		if err := s.ctx.Store().Users().Update(ctx, u); err != nil {
			return nil, err
		}
	}

	meta, _ := s.userMeta.FindOne(ctx, adapter.Eq("user_id", res.ID))
	if meta == nil {
		meta = &UserMetadata{
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
	_ = s.saveUserMetadata(ctx, meta)

	return s.GetUser(ctx, res.ID)
}

func (s *service) DeleteUser(ctx context.Context, id string) error {
	if id == "" {
		return ErrNotFound
	}
	_, _ = s.userMeta.Delete(ctx, adapter.Eq("user_id", id))
	if s.ctx != nil && s.ctx.Store() != nil && s.ctx.Store().Users() != nil {
		return s.ctx.Store().Users().Delete(ctx, id)
	}
	return nil
}

func (s *service) ListUsers(ctx context.Context, startIndex, count int) (*v2.ListResponse, error) {
	if count <= 0 {
		count = 100
	}
	if startIndex < 1 {
		startIndex = 1
	}

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

	now := s.now()
	gID := generateID("grp")
	rec := &GroupRecord{
		ID:          gID,
		DisplayName: res.DisplayName,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	for _, m := range res.Members {
		rec.MemberIDs = append(rec.MemberIDs, m.Value)
	}

	if err := s.groups.Create(ctx, rec); err != nil {
		return nil, err
	}

	return s.GetGroup(ctx, gID)
}

func (s *service) GetGroup(ctx context.Context, id string) (*v2.GroupResource, error) {
	if id == "" {
		return nil, ErrNotFound
	}
	rec, err := s.groups.FindOne(ctx, adapter.Eq("id", id))
	if errors.Is(err, adapter.ErrNotFound) || rec == nil {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
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

	rec, err := s.groups.FindOne(ctx, adapter.Eq("id", res.ID))
	if errors.Is(err, adapter.ErrNotFound) || rec == nil {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	now := s.now()
	rec.DisplayName = res.DisplayName
	rec.UpdatedAt = now
	rec.MemberIDs = nil
	for _, m := range res.Members {
		rec.MemberIDs = append(rec.MemberIDs, m.Value)
	}

	affected, err := s.groups.Update(ctx, []adapter.Condition{adapter.Eq("id", res.ID)}, map[string]any{
		"display_name": rec.DisplayName,
		"member_ids":   rec.MemberIDs,
		"updated_at":   now,
	})
	if err != nil {
		return nil, err
	}
	if affected == 0 {
		return nil, ErrNotFound
	}

	return s.GetGroup(ctx, res.ID)
}

func (s *service) DeleteGroup(ctx context.Context, id string) error {
	if id == "" {
		return ErrNotFound
	}
	affected, err := s.groups.Delete(ctx, adapter.Eq("id", id))
	if err != nil {
		return err
	}
	if affected == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *service) ListGroups(ctx context.Context, startIndex, count int) (*v2.ListResponse, error) {
	groups, err := s.groups.FindMany(ctx, adapter.Query{
		Model: ModelSCIMGroups,
	})
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
