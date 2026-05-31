package jwtauth

import "errors"

var (
	ErrMissingToken       = errors.New("missing token")
	ErrInvalidToken       = errors.New("invalid token")
	ErrInvalidTokenType   = errors.New("invalid token type")
	ErrTokenRevoked       = errors.New("token revoked")
	ErrTokenExpired       = errors.New("token expired")
	ErrInvalidBearerToken = errors.New("invalid bearer token")
)
