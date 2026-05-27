package jwtauth

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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

type AccessTokenClaims struct {
	UserID    int64
	IssuedAt  int64
	ExpiresAt int64
	Extra     map[string]interface{}
}

type RefreshTokenClaims struct {
	UserID    int64
	JTI       string
	IssuedAt  int64
	ExpiresAt int64
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

func (m *Manager) GenerateTokenPair(userID int64, extra map[string]interface{}) (*TokenPair, error) {
	at, err := m.generateAccessToken(userID, extra)
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
		claims[k] = normalizeValue(v)
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
		"jti":     fmt.Sprintf("%d-%d", userID, time.Now().UnixNano()),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(m.secret)
}

func (m *Manager) ValidateAccessToken(tokenStr string) (int64, map[string]interface{}, error) {
	claims, err := m.ValidateAccessTokenDetailed(tokenStr)
	if err != nil {
		return 0, nil, err
	}

	return claims.UserID, claims.Extra, nil
}

func (m *Manager) ValidateAccessTokenDetailed(tokenStr string) (*AccessTokenClaims, error) {
	parsed, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		if t.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return m.secret, nil
	})
	if err != nil {
		return nil, err
	}

	if !parsed.Valid {
		return nil, errors.New("invalid token")
	}

	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid claims")
	}

	if claims["type"] != "access" {
		return nil, errors.New("not access token")
	}

	userID, err := claimInt64(claims, "user_id")
	if err != nil {
		return nil, err
	}

	iat, err := claimInt64(claims, "iat")
	if err != nil {
		return nil, err
	}

	exp, err := claimInt64(claims, "exp")
	if err != nil {
		return nil, err
	}

	extras := make(map[string]interface{})
	for k, v := range claims {
		if k == "user_id" || k == "type" || k == "exp" || k == "iat" || k == "jti" {
			continue
		}
		extras[k] = normalizeValue(v)
	}

	return &AccessTokenClaims{
		UserID:    userID,
		IssuedAt:  iat,
		ExpiresAt: exp,
		Extra:     extras,
	}, nil
}

func (m *Manager) ValidateRefreshToken(tokenStr string) (userID int64, jti string, exp int64, err error) {
	claims, err := m.ValidateRefreshTokenDetailed(tokenStr)
	if err != nil {
		return 0, "", 0, err
	}

	return claims.UserID, claims.JTI, claims.ExpiresAt, nil
}

func (m *Manager) ValidateRefreshTokenDetailed(tokenStr string) (*RefreshTokenClaims, error) {
	parsed, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		if t.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return m.secret, nil
	})
	if err != nil {
		return nil, err
	}

	if !parsed.Valid {
		return nil, errors.New("invalid refresh token")
	}

	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid claims")
	}

	if claims["type"] != "refresh" {
		return nil, errors.New("not refresh token")
	}

	userID, err := claimInt64(claims, "user_id")
	if err != nil {
		return nil, err
	}

	jti, ok := claims["jti"].(string)
	if !ok || jti == "" {
		return nil, errors.New("jti not found")
	}

	iat, err := claimInt64(claims, "iat")
	if err != nil {
		return nil, err
	}

	exp, err := claimInt64(claims, "exp")
	if err != nil {
		return nil, err
	}

	return &RefreshTokenClaims{
		UserID:    userID,
		JTI:       jti,
		IssuedAt:  iat,
		ExpiresAt: exp,
	}, nil
}

func HashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

func GetExp(tokenStr string) (int64, error) {
	tok, _, err := new(jwt.Parser).ParseUnverified(tokenStr, jwt.MapClaims{})
	if err != nil {
		return 0, err
	}

	claims := tok.Claims.(jwt.MapClaims)

	expf, ok := claims["exp"].(float64)
	if !ok {
		return 0, errors.New("exp not found")
	}

	return int64(expf), nil
}

func claimInt64(claims jwt.MapClaims, name string) (int64, error) {
	v, ok := claims[name]
	if !ok {
		return 0, fmt.Errorf("%s not found", name)
	}

	switch val := v.(type) {
	case float64:
		return int64(val), nil
	case int64:
		return val, nil
	case int:
		return int64(val), nil
	case json.Number:
		return val.Int64()
	default:
		return 0, fmt.Errorf("%s not found", name)
	}
}

func normalizeValue(v interface{}) interface{} {
	switch val := v.(type) {
	case int:
		return int64(val)
	case int8:
		return int64(val)
	case int16:
		return int64(val)
	case int32:
		return int64(val)
	case int64:
		return val
	case uint:
		return int64(val)
	case uint8:
		return int64(val)
	case uint16:
		return int64(val)
	case uint32:
		return int64(val)
	case uint64:
		return int64(val)
	case float32:
		if val == float32(int64(val)) {
			return int64(val)
		}
		return float64(val)
	case float64:
		if val == float64(int64(val)) {
			return int64(val)
		}
		return val
	default:
		return v
	}
}
