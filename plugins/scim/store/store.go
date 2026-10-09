package store

import (
	"context"
	"errors"
	"time"
)

var (
	ErrNotFound = errors.New("scim/store: not found")
	ErrConflict = errors.New("scim/store: conflict")
)

type UserMetadata struct {
	UserID     string
	ExternalID string
	Active     bool
	GivenName  string
	FamilyName string
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

type GroupRecord struct {
	ID          string
	DisplayName string
	MemberIDs   []string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type Store interface {
	SaveUserMetadata(ctx context.Context, meta *UserMetadata) error
	GetUserMetadata(ctx context.Context, userID string) (*UserMetadata, error)
	GetUserMetadataByExternalID(ctx context.Context, externalID string) (*UserMetadata, error)
	DeleteUserMetadata(ctx context.Context, userID string) error

	CreateGroup(ctx context.Context, grp *GroupRecord) error
	GetGroup(ctx context.Context, id string) (*GroupRecord, error)
	ListGroups(ctx context.Context) ([]*GroupRecord, error)
	UpdateGroup(ctx context.Context, grp *GroupRecord) error
	DeleteGroup(ctx context.Context, id string) error
}
