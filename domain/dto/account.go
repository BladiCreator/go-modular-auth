package dto

type (
	// CreateAccountParams defines parameters for creating an authentication provider credentials account.
	CreateAccountParams struct {
		UserID   string `json:"userId" binding:"required"`
		Provider string `json:"provider" binding:"required"`
		Password string `json:"-"`
	}
)
