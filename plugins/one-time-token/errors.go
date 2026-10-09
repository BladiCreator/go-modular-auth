package ott

import "errors"

var (
	ErrInvalidSubject  = errors.New("ott: subject is required")
	ErrInvalidToken    = errors.New("ott: invalid or expired token")
	ErrInvalidTTL      = errors.New("ott: ttl must be positive")
)
