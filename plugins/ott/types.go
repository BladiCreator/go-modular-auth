package ott

import (
	"github.com/BladiCreator/go-modular-auth/domain/entity"
)

// GenerateTokenParams defines input parameters when requesting the issuance of a new One-Time Token.
type GenerateTokenParams struct {
	// SessionToken is the raw token string of the active session to bind to the OTT.
	SessionToken string `json:"session_token"`

	// IsClientReq indicates whether the token generation request originated directly from a client HTTP request.
	IsClientReq bool `json:"is_client_req"`
}

// GenerateTokenResponse contains the generated raw One-Time Token string returned to the caller.
type GenerateTokenResponse struct {
	// Token is the issued single-use token.
	Token string `json:"token"`
}

// VerifyTokenParams defines input parameters when verifying and consuming an OTT.
type VerifyTokenParams struct {
	// Token is the raw One-Time Token string to verify and consume.
	Token string `json:"token"`
}

// VerifyTokenResponse contains the validated active Session and associated User entities.
type VerifyTokenResponse struct {
	// Session is the retrieved active session associated with the consumed token.
	Session *entity.Session `json:"session"`

	// User is the account entity owning the active session.
	User *entity.User `json:"user"`
}
