# Пакет `jwtauth`

Пакет `jwtauth` предоставляет удобный и безопасный способ работы с JWT-токенами:

* генерация access и refresh токенов
* валидация токенов
* интеграция с Gin через middleware
* blacklist для отзыва конкретного access-токена через Redis
* отзыв всех токенов пользователя по `iat` через Redis
* извлечение `userID` из контекста

---

## Установка

```go
import "github.com/sladkoelllka/jwtauth"
```

---

## 1. Создание менеджера токенов

```go
secret := "supersecretkey"
mgr := jwtauth.NewManager(secret)
```

Настройка TTL для токенов:

```go
mgr.WithDurations(30*time.Minute, 60*24*time.Hour) // access=30мин, refresh=60дн
```

---

## 2. Генерация токенов

```go
userID := int64(42)
extraClaims := map[string]interface{}{
    "role": "admin",
}

tokens, err := mgr.GenerateTokenPair(userID, extraClaims)
if err != nil {
    // обработка ошибки
}
```

---

## 3. Валидация токенов

### Access-токен

```go
userID, extras, err := mgr.ValidateAccessToken(tokens.AccessToken)
if err != nil {
    // токен недействителен
}
```

### Refresh-токен

```go
userID, jti, exp, err := mgr.ValidateRefreshToken(tokens.RefreshToken)
if err != nil {
    // refresh токен недействителен
}
```

Для проверки отзыва токенов пользователя используйте detailed-методы:

```go
accessClaims, err := mgr.ValidateAccessTokenDetailed(tokens.AccessToken)
refreshClaims, err := mgr.ValidateRefreshTokenDetailed(tokens.RefreshToken)
```

Они возвращают `iat`, по которому можно понять, был ли токен выпущен до блокировки пользователя.

---

## 4. Blacklist

Blacklist отзывает конкретный access-токен, например при logout.

```go
redisClient := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
bl := jwtauth.NewBlacklist(redisClient)

exp, err := jwtauth.GetExp(tokens.AccessToken)
if err == nil {
    err = bl.Add(tokens.AccessToken, exp)
}
```

Проверка наличия токена в blacklist:

```go
blocked, err := bl.Exists(tokens.AccessToken)
if err != nil {
    // ошибка Redis
}
if blocked {
    // token revoked
}
```

Токены хранятся в Redis в виде SHA256-хэша.

---

## 5. Отзыв всех токенов пользователя

Для блокировки пользователя используйте `UserRevocationStore`. Он хранит timestamp, до которого все токены пользователя считаются отозванными.

```go
revocations := jwtauth.NewUserRevocationStore(redisClient)
err := revocations.RevokeUser(userID, time.Now())
```

По умолчанию запись хранится без TTL. Если в вашем сценарии нужен срок хранения, задайте его явно:

```go
revocations.WithTTL(31 * 24 * time.Hour)
```

Проверка access-токена:

```go
claims, err := mgr.ValidateAccessTokenDetailed(accessToken)
if err != nil {
    // токен недействителен
}

revoked, err := revocations.IsRevoked(claims.UserID, claims.IssuedAt)
if err != nil {
    // ошибка Redis
}
if revoked {
    // токен был выпущен до блокировки пользователя
}
```

При разблокировке пользователя не удаляйте revocation-запись: старые токены не должны оживать. Пользователь должен получить новую пару токенов через login.

---

## 6. Gin Middleware

Подключение middleware к маршрутам Gin:

```go
r := gin.Default()
bl := jwtauth.NewBlacklist(redisClient)
revocations := jwtauth.NewUserRevocationStore(redisClient)
r.Use(jwtauth.GinMiddlewareWithUserRevocation(mgr, bl, revocations))

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

* наличие заголовка `Authorization: Bearer <token>`
* корректность подписи и срок действия токена
* blacklist конкретного access-токена
* отзыв всех токенов пользователя через `UserRevocationStore`
* помещает `user_id` в контекст Gin (`c.Set("user_id", userID)`)

---

## 7. Извлечение userID из контекста

### Стандартный `context.Context`

```go
userID, ok := jwtauth.UserIDFromContext(ctx)
```

### Gin `*gin.Context`

```go
userID, ok := jwtauth.UserIDFromGinContext(c)
```

---

## Рекомендации по использованию

* Для доступа к защищённым маршрутам используйте Gin middleware.
* Для logout используйте blacklist конкретного access-токена.
* Для блокировки пользователя используйте `UserRevocationStore`, а не blacklist.
* Всегда валидируйте refresh-токены через `ValidateRefreshToken` или `ValidateRefreshTokenDetailed`.
* Храните секрет JWT в безопасном месте: env, Vault или secrets manager.
