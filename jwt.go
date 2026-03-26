package jwtauth

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Manager struct {
	secret     []byte
	accessTTL  time.Duration
	refreshTTL time.Duration
}

type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
}

func NewManager(secret string) *Manager {
	return &Manager{
		secret:     []byte(secret),
		accessTTL:  15 * time.Minute,
		refreshTTL: 30 * 24 * time.Hour,
	}
}

func (m *Manager) WithDurations(access, refresh time.Duration) *Manager {
	m.accessTTL = access
	m.refreshTTL = refresh
	return m
}

// --------------------
// Генерация токенов
// --------------------

func (m *Manager) GenerateTokenPair(userID int64, extraClaims map[string]interface{}) (*TokenPair, error) {
	at, err := m.generateAccessToken(userID, extraClaims)
	if err != nil {
		return nil, err
	}

	rt, err := m.generateRefreshToken(userID)
	if err != nil {
		return nil, err
	}

	return &TokenPair{
		AccessToken:  at,
		RefreshToken: rt,
		ExpiresIn:    int64(m.accessTTL.Seconds()),
	}, nil

}

func (m *Manager) generateAccessToken(userID int64, extra map[string]interface{}) (string, error) {
	claims := jwt.MapClaims{
		"user_id": userID,
		"type":    "access",
		"exp":     time.Now().Add(m.accessTTL).Unix(),
		"iat":     time.Now().Unix(),
	}

	for k, v := range extra {
		claims[k] = v
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(m.secret)

}

func (m *Manager) generateRefreshToken(userID int64) (string, error) {
	claims := jwt.MapClaims{
		"user_id": userID,
		"type":    "refresh",
		"exp":     time.Now().Add(m.refreshTTL).Unix(),
		"iat":     time.Now().Unix(),
		"jti":     fmt.Sprintf("%d-%d", userID, time.Now().UnixNano()), // уникальный идентификатор
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(m.secret)

}

// --------------------
// Валидация токенов
// --------------------

func (m *Manager) ValidateAccessToken(tokenStr string) (int64, map[string]interface{}, error) {
	parsed, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		if t.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return m.secret, nil
	})
	if err != nil {
		return 0, nil, err
	}
	if !parsed.Valid {
		return 0, nil, errors.New("invalid token")
	}

	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return 0, nil, errors.New("invalid claims")
	}

	userIDf, ok := claims["user_id"].(float64)
	if !ok {
		return 0, nil, errors.New("user_id not found")
	}
	userID := int64(userIDf)

	extras := make(map[string]interface{})
	for k, v := range claims {
		if k == "user_id" || k == "type" || k == "exp" || k == "iat" || k == "jti" {
			continue
		}
		extras[k] = v
	}

	return userID, extras, nil

}

func (m *Manager) ValidateRefreshToken(tokenStr string) (int64, error) {
	parsed, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		if t.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return m.secret, nil
	})
	if err != nil {
		return 0, err
	}
	if !parsed.Valid {
		return 0, errors.New("invalid refresh token")
	}

	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return 0, errors.New("invalid claims")
	}

	typ, ok := claims["type"].(string)
	if !ok || typ != "refresh" {
		return 0, errors.New("token is not a refresh token")
	}

	userIDf, ok := claims["user_id"].(float64)
	if !ok {
		return 0, errors.New("user_id not found")
	}

	return int64(userIDf), nil

}

// --------------------
// HashToken для blacklist
// --------------------

func HashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}
