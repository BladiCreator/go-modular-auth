// Package customsession provides dynamic session payload transformation and dynamic additional fields management.
package customsession

import (
	"context"
	"net/http"

	"github.com/BladiCreator/go-modular-auth/domain/dto"
	"github.com/BladiCreator/go-modular-auth/domain/entity"
)

// TransformSessionFunc is the callback signature for transforming and enriching session response data dynamically per request.
type TransformSessionFunc func(ctx context.Context, sessionData *dto.SessionData, req *http.Request) (any, error)

// CustomSessionData is the standard response container holding user, session, and dynamic extra payload fields.
type CustomSessionData struct {
	User    *entity.User    `json:"user"`
	Session *entity.Session `json:"session"`
	Extra   map[string]any  `json:"extra,omitzero"`
}
