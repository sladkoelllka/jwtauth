# Пакет `jwtauth`

Пакет `jwtauth` предоставляет удобный и безопасный способ работы с JWT-токенами:

* генерация access и refresh токенов
* валидация токенов
* интеграция с Gin через middleware
* blacklist для отзыва токенов (Redis)
* извлечение `userID` из контекста

---

## Установка

```go
import "gitlab.legion.devel/common-backend/jwtauth"
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

fmt.Println("Access:", tokens.AccessToken)
fmt.Println("Refresh:", tokens.RefreshToken)
fmt.Println("ExpiresIn:", tokens.ExpiresIn)
```

---

## 3. Валидация токенов

### Access-токен

```go
userID, extras, err := mgr.ValidateAccessToken(tokens.AccessToken)
if err != nil {
    // токен недействителен
}
fmt.Println(userID, extras)
```

### Refresh-токен

```go
userID, err := mgr.ValidateRefreshToken(tokens.RefreshToken)
if err != nil {
    // refresh токен недействителен
}
```

---

## 4. Blacklist (отзыв токенов)

Создание blacklist с TTL:

```go
redisClient := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
bl := jwtauth.NewBlacklist(redisClient, 24*time.Hour)
```

Добавление токена в blacklist:

```go
err := bl.Add(tokens.AccessToken)
```

Проверка наличия токена в blacklist:

```go
blocked, _ := bl.Exists(tokens.AccessToken)
if blocked {
    fmt.Println("Token revoked")
}
```

Удаление токена из blacklist:

```go
bl.Remove(tokens.AccessToken)
```

> Примечание: токены хранятся в Redis в виде SHA256-хэша для безопасности.

---

## 5. Gin Middleware

Подключение middleware к маршрутам Gin:

```go
r := gin.Default()
r.Use(jwtauth.GinMiddleware(mgr))

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
* помещает `user_id` в контекст Gin (`c.Set("user_id", userID)`)

---

## 6. Хэширование токена

Для безопасного хранения в blacklist:

```go
hash := jwtauth.HashToken(tokens.AccessToken)
fmt.Println(hash)
```

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

* Для доступа к защищённым маршрутам всегда используйте Gin middleware.
* Для отзыва токенов используйте blacklist и проверяйте перед выдачей доступа.
* Всегда валидируйте refresh-токены через `ValidateRefreshToken`.
* Храните секрет JWT в безопасном месте (env, Vault, secrets manager).
* Для production можно добавлять уникальный `jti` в refresh-токены для идентификации.
