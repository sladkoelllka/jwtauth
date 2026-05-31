package jwtauth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Manager struct {
	secret    []byte
	accessTTL time.Duration
	issuer    string
	audience  []string
}

type Options struct {
	Secret    string
	AccessTTL time.Duration
	Issuer    string
	Audience  []string
}

type AccessTokenOptions struct {
	SessionID string
	Extra     map[string]interface{}
}

type AccessTokenClaims struct {
	UserID    int64
	SessionID string
	IssuedAt  int64
	ExpiresAt int64
	Issuer    string
	Audience  []string
	Extra     map[string]interface{}
}

func NewManager(opts Options) *Manager {
	accessTTL := opts.AccessTTL
	if accessTTL == 0 {
		accessTTL = 15 * time.Minute
	}

	return &Manager{
		secret:    []byte(opts.Secret),
		accessTTL: accessTTL,
		issuer:    opts.Issuer,
		audience:  append([]string(nil), opts.Audience...),
	}
}

func (m *Manager) AccessTTL() time.Duration {
	return m.accessTTL
}

func (m *Manager) GenerateAccessToken(userID int64, opts AccessTokenOptions) (string, error) {
	if len(m.secret) == 0 {
		return "", errors.New("jwt secret is empty")
	}

	now := time.Now()
	claims := jwt.MapClaims{
		"user_id": userID,
		"type":    "access",
		"exp":     now.Add(m.accessTTL).Unix(),
		"iat":     now.Unix(),
	}

	if opts.SessionID != "" {
		claims["sid"] = opts.SessionID
	}
	if m.issuer != "" {
		claims["iss"] = m.issuer
	}
	if len(m.audience) > 0 {
		claims["aud"] = m.audience
	}

	for k, v := range opts.Extra {
		if isReservedClaim(k) {
			return "", fmt.Errorf("reserved claim %q", k)
		}
		claims[k] = normalizeValue(v)
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
	if len(m.secret) == 0 {
		return nil, errors.New("jwt secret is empty")
	}

	parser := jwt.NewParser(jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}))
	parsed, err := parser.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		return m.secret, nil
	})
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrTokenExpired
		}
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	if !parsed.Valid {
		return nil, ErrInvalidToken
	}

	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return nil, ErrInvalidToken
	}
	if claims["type"] != "access" {
		return nil, ErrInvalidTokenType
	}
	if err := m.validateRegisteredClaims(claims); err != nil {
		return nil, err
	}

	userID, err := claimInt64(claims, "user_id")
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	iat, err := claimInt64(claims, "iat")
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	exp, err := claimInt64(claims, "exp")
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	extras := make(map[string]interface{})
	for k, v := range claims {
		if isReservedClaim(k) {
			continue
		}
		extras[k] = normalizeValue(v)
	}

	return &AccessTokenClaims{
		UserID:    userID,
		SessionID: stringClaim(claims, "sid"),
		IssuedAt:  iat,
		ExpiresAt: exp,
		Issuer:    stringClaim(claims, "iss"),
		Audience:  audienceClaim(claims),
		Extra:     extras,
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

	claims, ok := tok.Claims.(jwt.MapClaims)
	if !ok {
		return 0, ErrInvalidToken
	}

	expf, ok := claims["exp"].(float64)
	if !ok {
		return 0, errors.New("exp not found")
	}

	return int64(expf), nil
}

func GenerateOpaqueRefreshToken() (string, error) {
	return GenerateOpaqueToken(32)
}

func GenerateOpaqueToken(byteLen int) (string, error) {
	if byteLen < 32 {
		byteLen = 32
	}
	b := make([]byte, byteLen)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (m *Manager) validateRegisteredClaims(claims jwt.MapClaims) error {
	if m.issuer != "" && stringClaim(claims, "iss") != m.issuer {
		return fmt.Errorf("%w: invalid issuer", ErrInvalidToken)
	}
	if len(m.audience) > 0 && !audienceMatches(audienceClaim(claims), m.audience) {
		return fmt.Errorf("%w: invalid audience", ErrInvalidToken)
	}
	return nil
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

func isReservedClaim(name string) bool {
	switch name {
	case "user_id", "type", "exp", "iat", "jti", "sid", "iss", "aud", "nbf", "sub":
		return true
	default:
		return false
	}
}

func stringClaim(claims jwt.MapClaims, name string) string {
	v, _ := claims[name].(string)
	return v
}

func audienceClaim(claims jwt.MapClaims) []string {
	switch v := claims["aud"].(type) {
	case string:
		return []string{v}
	case []string:
		return append([]string(nil), v...)
	case []interface{}:
		values := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				values = append(values, s)
			}
		}
		return values
	default:
		return nil
	}
}

func audienceMatches(actual, expected []string) bool {
	for _, a := range actual {
		for _, e := range expected {
			if a == e {
				return true
			}
		}
	}
	return false
}
