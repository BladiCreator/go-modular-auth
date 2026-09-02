package dto

import (
	"github.com/BladiCreator/go-modular-auth/domain/entity"
)

type (
	// CreateAccountParams defines parameters for creating an authentication provider credentials account.
	CreateAccountParams struct {
		UserID   string `json:"userId" binding:"required"`
		Provider string `json:"provider" binding:"required"`
		Password string `json:"-"`
		entity.ExtraContainer
	}
)
