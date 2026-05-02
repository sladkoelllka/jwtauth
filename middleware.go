package jwtauth

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/gin-gonic/gin"
)

type userKey struct{}
type authKey struct{}

const ginAuthKey = "auth"

type AuthInfo struct {
	UserID int64
	Claims map[string]interface{}
}

type TokenBlacklist interface {
	Exists(token string) (bool, error)
}

var (
	ErrMissingToken   = errors.New("missing token")
	ErrTokenRevoked   = errors.New("token revoked")
	ErrBlacklistCheck = errors.New("blacklist check failed")
)

func AuthenticateBearer(header string, mgr *Manager, bl TokenBlacklist) (AuthInfo, error) {
	if header == "" {
		return AuthInfo{}, ErrMissingToken
	}

	token := strings.TrimPrefix(header, "Bearer ")

	exists, err := bl.Exists(token)
	if err != nil {
		return AuthInfo{}, fmt.Errorf("%w: %v", ErrBlacklistCheck, err)
	}
	if exists {
		return AuthInfo{}, ErrTokenRevoked
	}

	userID, claims, err := mgr.ValidateAccessToken(token)
	if err != nil {
		return AuthInfo{}, err
	}

	return AuthInfo{
		UserID: userID,
		Claims: claims,
	}, nil
}

func WithAuthInfo(ctx context.Context, auth AuthInfo) context.Context {
	return context.WithValue(ctx, authKey{}, auth)
}

func AuthInfoFromContext(ctx context.Context) (AuthInfo, bool) {
	v := ctx.Value(authKey{})
	auth, ok := v.(AuthInfo)
	return auth, ok
}

func UserIDFromContext(ctx context.Context) (int64, bool) {
	if auth, ok := AuthInfoFromContext(ctx); ok {
		return auth.UserID, true
	}

	v := ctx.Value(userKey{})
	id, ok := v.(int64)
	return id, ok
}

func ClaimsFromContext(ctx context.Context) (map[string]interface{}, bool) {
	auth, ok := AuthInfoFromContext(ctx)
	if !ok {
		return nil, false
	}

	return auth.Claims, true
}

func AuthInfoFromGinContext(c *gin.Context) (AuthInfo, bool) {
	v, ok := c.Get(ginAuthKey)
	if !ok {
		return AuthInfo{}, false
	}

	auth, ok := v.(AuthInfo)
	return auth, ok
}

func UserIDFromGinContext(c *gin.Context) (int64, bool) {
	if auth, ok := AuthInfoFromGinContext(c); ok {
		return auth.UserID, true
	}

	v, ok := c.Get("user_id")
	if !ok {
		return 0, false
	}
	id, ok := v.(int64)
	return id, ok
}

func ClaimsFromGinContext(c *gin.Context) (map[string]interface{}, bool) {
	auth, ok := AuthInfoFromGinContext(c)
	if !ok {
		return nil, false
	}

	return auth.Claims, true
}

func GinMiddleware(mgr *Manager, bl TokenBlacklist) gin.HandlerFunc {
	return func(c *gin.Context) {
		auth, err := AuthenticateBearer(c.GetHeader("Authorization"), mgr, bl)
		if errors.Is(err, ErrMissingToken) {
			c.AbortWithStatusJSON(401, gin.H{"error": "missing token"})
			return
		}
		if errors.Is(err, ErrTokenRevoked) {
			c.AbortWithStatusJSON(401, gin.H{"error": "token revoked"})
			return
		}
		if errors.Is(err, ErrBlacklistCheck) {
			c.AbortWithStatusJSON(500, gin.H{"error": "internal error"})
			return
		}
		if err != nil {
			c.AbortWithStatusJSON(401, gin.H{"error": "invalid token"})
			return
		}

		c.Set("user_id", auth.UserID)
		c.Set(ginAuthKey, auth)
		c.Request = c.Request.WithContext(WithAuthInfo(c.Request.Context(), auth))
		c.Next()
	}
}
