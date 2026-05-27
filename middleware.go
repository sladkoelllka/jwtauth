package jwtauth

import (
	"context"
	"strings"

	"github.com/gin-gonic/gin"
)

type userKey struct{}

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

func GinMiddleware(mgr *Manager, bl *Blacklist) gin.HandlerFunc {
	return func(c *gin.Context) {
		hdr := c.GetHeader("Authorization")
		if hdr == "" {
			c.AbortWithStatusJSON(401, gin.H{"error": "missing token"})
			return
		}

		token := strings.TrimPrefix(hdr, "Bearer ")

		exists, err := bl.Exists(token)
		if err != nil {
			c.AbortWithStatusJSON(500, gin.H{"error": "internal error"})
			return
		}
		if exists {
			c.AbortWithStatusJSON(401, gin.H{"error": "token revoked"})
			return
		}

		userID, _, err := mgr.ValidateAccessToken(token)
		if err != nil {
			c.AbortWithStatusJSON(401, gin.H{"error": "invalid token"})
			return
		}

		c.Set("user_id", userID)
		c.Next()
	}
}

func GinMiddlewareWithUserRevocation(mgr *Manager, bl *Blacklist, revocations *UserRevocationStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		hdr := c.GetHeader("Authorization")
		if hdr == "" {
			c.AbortWithStatusJSON(401, gin.H{"error": "missing token"})
			return
		}

		token := strings.TrimPrefix(hdr, "Bearer ")

		exists, err := bl.Exists(token)
		if err != nil {
			c.AbortWithStatusJSON(500, gin.H{"error": "internal error"})
			return
		}
		if exists {
			c.AbortWithStatusJSON(401, gin.H{"error": "token revoked"})
			return
		}

		claims, err := mgr.ValidateAccessTokenDetailed(token)
		if err != nil {
			c.AbortWithStatusJSON(401, gin.H{"error": "invalid token"})
			return
		}

		revoked, err := revocations.IsRevoked(claims.UserID, claims.IssuedAt)
		if err != nil {
			c.AbortWithStatusJSON(500, gin.H{"error": "internal error"})
			return
		}
		if revoked {
			c.AbortWithStatusJSON(401, gin.H{"error": "token revoked"})
			return
		}

		c.Set("user_id", claims.UserID)
		c.Next()
	}
}
