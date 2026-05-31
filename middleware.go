package jwtauth

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

type userKey struct{}
type claimsKey struct{}

func UserIDFromContext(ctx context.Context) (int64, bool) {
	v := ctx.Value(userKey{})
	id, ok := v.(int64)
	return id, ok
}

func UserIDFromGinContext(c *gin.Context) (int64, bool) {
	v, ok := c.Get("user_id")
	if !ok {
		return 0, false
	}
	id, ok := v.(int64)
	return id, ok
}

func AccessClaimsFromGinContext(c *gin.Context) (*AccessTokenClaims, bool) {
	v, ok := c.Get("access_claims")
	if !ok {
		return nil, false
	}
	claims, ok := v.(*AccessTokenClaims)
	return claims, ok
}

func AccessClaimsFromContext(ctx context.Context) (*AccessTokenClaims, bool) {
	v := ctx.Value(claimsKey{})
	claims, ok := v.(*AccessTokenClaims)
	return claims, ok
}

func ExtractBearerToken(header string) (string, error) {
	parts := strings.Fields(header)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || parts[1] == "" {
		return "", ErrInvalidBearerToken
	}
	return parts[1], nil
}

func GinMiddleware(mgr *Manager, bl *Blacklist) gin.HandlerFunc {
	return func(c *gin.Context) {
		authenticateGin(c, mgr, bl, nil)
	}
}

func GinMiddlewareWithUserRevocation(mgr *Manager, bl *Blacklist, revocations *UserRevocationStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		authenticateGin(c, mgr, bl, revocations)
	}
}

func authenticateGin(c *gin.Context, mgr *Manager, bl *Blacklist, revocations *UserRevocationStore) {
	if mgr == nil {
		abortAuth(c, http.StatusInternalServerError, errors.New("jwt manager is nil"))
		return
	}

	hdr := c.GetHeader("Authorization")
	if hdr == "" {
		abortAuth(c, http.StatusUnauthorized, ErrMissingToken)
		return
	}

	token, err := ExtractBearerToken(hdr)
	if err != nil {
		abortAuth(c, http.StatusUnauthorized, err)
		return
	}

	exists, err := bl.ExistsContext(c.Request.Context(), token)
	if err != nil {
		abortAuth(c, http.StatusInternalServerError, err)
		return
	}
	if exists {
		abortAuth(c, http.StatusUnauthorized, ErrTokenRevoked)
		return
	}

	claims, err := mgr.ValidateAccessTokenDetailed(token)
	if err != nil {
		abortAuth(c, http.StatusUnauthorized, err)
		return
	}

	revoked, err := revocations.IsRevokedContext(c.Request.Context(), claims.UserID, claims.IssuedAt)
	if err != nil {
		abortAuth(c, http.StatusInternalServerError, err)
		return
	}
	if revoked {
		abortAuth(c, http.StatusUnauthorized, ErrTokenRevoked)
		return
	}

	c.Set("user_id", claims.UserID)
	c.Set("access_claims", claims)
	ctx := context.WithValue(c.Request.Context(), userKey{}, claims.UserID)
	ctx = context.WithValue(ctx, claimsKey{}, claims)
	c.Request = c.Request.WithContext(ctx)
	c.Next()
}

func abortAuth(c *gin.Context, status int, err error) {
	message := "invalid token"
	switch {
	case errors.Is(err, ErrMissingToken):
		message = "missing token"
	case errors.Is(err, ErrInvalidBearerToken):
		message = "invalid authorization token format"
	case errors.Is(err, ErrTokenRevoked):
		message = "token revoked"
	case errors.Is(err, ErrTokenExpired):
		message = "token expired"
	case status == http.StatusInternalServerError:
		message = "internal error"
	}
	c.AbortWithStatusJSON(status, gin.H{"error": message})
}
