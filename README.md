# jwtauth

`jwtauth` — это небольшой production-oriented пакет для аутентификации по access-токенам в Go-сервисах.

Пакет намеренно отвечает только за:

* короткоживущие JWT access-токены;
* генерацию opaque refresh-токенов;
* хеширование токенов;
* blacklist access-токенов на базе Redis;
* отзыв всех токенов пользователя по `iat` на базе Redis;
* вспомогательные middleware для Gin.

Хранение и ротация refresh-токенов должны находиться на уровне auth/session-слоя приложения.
В базе данных храните только хеши refresh-токенов.

## Модель токенов

Рекомендуемый flow:

* access token: JWT, короткий TTL, stateless-валидация;
* refresh token: opaque random string, хранится в БД в виде хеша;
* logout текущей сессии: отозвать DB-сессию и добавить текущий access-токен в blacklist до его `exp`;
* logout со всех устройств / смена пароля: отозвать DB-сессии и установить timestamp отзыва пользователя в Redis.

Не кладите приватные данные профиля, роли, пары или отношений в claims access-токена, если устаревание этих данных явно не является допустимым.

## Manager

```go
mgr := jwtauth.NewManager(jwtauth.Options{
    Secret:    os.Getenv("JWT_SECRET"),
    AccessTTL: 15 * time.Minute,
    Issuer:    "relationship-companion-api",
    Audience:  []string{"mobile"},
})
```

Сгенерировать access-токен:

```go
accessToken, err := mgr.GenerateAccessToken(userID, jwtauth.AccessTokenOptions{
    SessionID: sessionID,
    Extra: map[string]interface{}{
        "client": "telegram-mini-app",
    },
})
```

Проверить access-токен:

```go
claims, err := mgr.ValidateAccessTokenDetailed(accessToken)
if err != nil {
    return err
}

userID := claims.UserID
sessionID := claims.SessionID
```

## Refresh-токены

Сгенерировать opaque refresh-токен:

```go
refreshToken, err := jwtauth.GenerateOpaqueRefreshToken()
if err != nil {
    return err
}

refreshTokenHash := jwtauth.HashToken(refreshToken)
```

Храните только хеш:

```sql
INSERT INTO auth_sessions (
    user_id,
    refresh_token_hash,
    refresh_token_expires_at
) VALUES ($1, $2, $3);
```

При refresh:

1. захешировать переданный refresh-токен;
2. загрузить и заблокировать DB-сессию по хешу;
3. проверить, что сессия активна и не истекла;
4. сгенерировать новый opaque refresh-токен;
5. заменить старый хеш новым в рамках той же транзакции;
6. выпустить новый access-токен.

## Blacklist

Blacklist нужен для отзыва конкретного access-токена до момента его истечения.

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

Проверить blacklist:

```go
blocked, err := blacklist.ExistsContext(ctx, accessToken)
```

Токены хранятся в Redis в виде SHA-256 хешей.

## Отзыв токенов пользователя

Используйте `UserRevocationStore`, чтобы инвалидировать все access-токены, выпущенные до определенного момента времени.

Это полезно для logout со всех устройств, смены пароля, блокировки аккаунта и событий безопасности.

```go
revocations := jwtauth.NewUserRevocationStore(redisClient).
    WithTTL(31 * 24 * time.Hour)

if err := revocations.RevokeUserContext(ctx, userID, time.Now()); err != nil {
    return err
}
```

Проверить отзыв:

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

Middleware проверяет:

* точный формат `Authorization: Bearer <token>`;
* подпись JWT и срок действия;
* что тип токена — `access`;
* опциональные issuer и audience;
* blacklist конкретного access-токена;
* timestamp отзыва всех токенов пользователя.

## Ошибки

Пакет предоставляет sentinel errors:

* `ErrMissingToken`;
* `ErrInvalidToken`;
* `ErrInvalidTokenType`;
* `ErrTokenRevoked`;
* `ErrTokenExpired`;
* `ErrInvalidBearerToken`.

Используйте `errors.Is`, чтобы классифицировать эти ошибки.
