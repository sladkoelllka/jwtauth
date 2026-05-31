# jwtauth

`jwtauth` is a small production-oriented package for access-token authentication in Go services.

The package intentionally handles only:

* short-lived JWT access tokens
* opaque refresh token generation
* token hashing
* Redis-backed access token blacklist
* Redis-backed user-wide revocation by `iat`
* Gin middleware helpers

Refresh token persistence and rotation must live in the application auth/session layer.
Store only refresh token hashes in your database.

## Token Model

Recommended flow:

* access token: JWT, short TTL, stateless validation
* refresh token: opaque random string, stored as hash in DB
* logout current session: revoke DB session and blacklist current access token until `exp`
* logout all/password change: revoke DB sessions and set user revocation timestamp in Redis

Do not put private profile, role, couple, or relationship data into access token claims unless stale data is explicitly acceptable.

## Manager

```go
mgr := jwtauth.NewManager(jwtauth.Options{
    Secret:    os.Getenv("JWT_SECRET"),
    AccessTTL: 15 * time.Minute,
    Issuer:    "relationship-companion-api",
    Audience:  []string{"mobile"},
})
```

Generate an access token:

```go
accessToken, err := mgr.GenerateAccessToken(userID, jwtauth.AccessTokenOptions{
    SessionID: sessionID,
    Extra: map[string]interface{}{
        "client": "telegram-mini-app",
    },
})
```

Validate an access token:

```go
claims, err := mgr.ValidateAccessTokenDetailed(accessToken)
if err != nil {
    return err
}

userID := claims.UserID
sessionID := claims.SessionID
```

## Refresh Tokens

Generate an opaque refresh token:

```go
refreshToken, err := jwtauth.GenerateOpaqueRefreshToken()
if err != nil {
    return err
}

refreshTokenHash := jwtauth.HashToken(refreshToken)
```

Persist only the hash:

```sql
INSERT INTO auth_sessions (
    user_id,
    refresh_token_hash,
    refresh_token_expires_at
) VALUES ($1, $2, $3);
```

On refresh:

1. hash the provided refresh token
2. load and lock the DB session by hash
3. verify the session is active and not expired
4. generate a new opaque refresh token
5. replace the old hash with the new hash in the same transaction
6. issue a new access token

## Blacklist

Blacklist is for revoking a concrete access token until its expiration.

```go
blacklist := jwtauth.NewBlacklist(redisClient)

exp, err := jwtauth.GetExp(accessToken)
if err != nil {
    return err
}

if err := blacklist.AddContext(ctx, accessToken, exp); err != nil {
    return err
}
```

Check blacklist:

```go
blocked, err := blacklist.ExistsContext(ctx, accessToken)
```

Tokens are stored in Redis as SHA-256 hashes.

## User Revocation

Use `UserRevocationStore` to invalidate all access tokens issued before a point in time.
This is useful for logout-all, password change, account lock, and security events.

```go
revocations := jwtauth.NewUserRevocationStore(redisClient).
    WithTTL(31 * 24 * time.Hour)

if err := revocations.RevokeUserContext(ctx, userID, time.Now()); err != nil {
    return err
}
```

Check revocation:

```go
revoked, err := revocations.IsRevokedContext(ctx, claims.UserID, claims.IssuedAt)
```

## Gin Middleware

```go
r := gin.Default()

blacklist := jwtauth.NewBlacklist(redisClient)
revocations := jwtauth.NewUserRevocationStore(redisClient)

r.Use(jwtauth.GinMiddlewareWithUserRevocation(mgr, blacklist, revocations))

r.GET("/private", func(c *gin.Context) {
    userID, ok := jwtauth.UserIDFromGinContext(c)
    if !ok {
        c.JSON(401, gin.H{"error": "user not found"})
        return
    }

    c.JSON(200, gin.H{"user_id": userID})
})
```

The middleware checks:

* exact `Authorization: Bearer <token>` format
* JWT signature and expiration
* token type is `access`
* optional issuer and audience
* concrete access-token blacklist
* user-wide revocation timestamp

## Errors

The package exposes sentinel errors:

* `ErrMissingToken`
* `ErrInvalidToken`
* `ErrInvalidTokenType`
* `ErrTokenRevoked`
* `ErrTokenExpired`
* `ErrInvalidBearerToken`

Use `errors.Is` to classify them.
