package jwtauth

import (
	"testing"
	"time"
)

func TestTokenPairGenerationValidation(t *testing.T) {
	mgr := NewManager("secret")
	mgr.WithDurations(1*time.Minute, 1*time.Hour)

	pair, err := mgr.GenerateTokenPair(123, map[string]interface{}{"foo": "bar"})
	if err != nil {
		t.Fatal(err)
	}

	uid, extras, err := mgr.ValidateAccessToken(pair.AccessToken)
	if err != nil {
		t.Fatalf("access validation failed: %v", err)
	}
	if uid != 123 {
		t.Fatalf("expected uid 123 got %d", uid)
	}
	if extras["foo"] != "bar" {
		t.Fatalf("extra claim missing")
	}

	uid2, _, _, err := mgr.ValidateRefreshToken(pair.RefreshToken)
	if err != nil {
		t.Fatalf("refresh validation failed: %v", err)
	}
	if uid2 != 123 {
		t.Fatalf("expected refresh uid 123 got %d", uid2)
	}
}

func TestDetailedValidationIncludesIssuedAt(t *testing.T) {
	mgr := NewManager("secret")
	mgr.WithDurations(1*time.Minute, 1*time.Hour)

	before := time.Now().Unix()
	pair, err := mgr.GenerateTokenPair(123, map[string]interface{}{"foo": "bar"})
	if err != nil {
		t.Fatal(err)
	}
	after := time.Now().Unix()

	accessClaims, err := mgr.ValidateAccessTokenDetailed(pair.AccessToken)
	if err != nil {
		t.Fatalf("access validation failed: %v", err)
	}
	if accessClaims.UserID != 123 {
		t.Fatalf("expected uid 123 got %d", accessClaims.UserID)
	}
	if accessClaims.IssuedAt < before || accessClaims.IssuedAt > after {
		t.Fatalf("unexpected access iat: %d", accessClaims.IssuedAt)
	}
	if accessClaims.ExpiresAt == 0 {
		t.Fatalf("expected access exp")
	}
	if accessClaims.Extra["foo"] != "bar" {
		t.Fatalf("extra claim missing")
	}

	refreshClaims, err := mgr.ValidateRefreshTokenDetailed(pair.RefreshToken)
	if err != nil {
		t.Fatalf("refresh validation failed: %v", err)
	}
	if refreshClaims.UserID != 123 {
		t.Fatalf("expected refresh uid 123 got %d", refreshClaims.UserID)
	}
	if refreshClaims.JTI == "" {
		t.Fatalf("expected refresh jti")
	}
	if refreshClaims.IssuedAt < before || refreshClaims.IssuedAt > after {
		t.Fatalf("unexpected refresh iat: %d", refreshClaims.IssuedAt)
	}
	if refreshClaims.ExpiresAt == 0 {
		t.Fatalf("expected refresh exp")
	}
}

func TestHashToken(t *testing.T) {
	h1 := HashToken("abc")
	h2 := HashToken("abc")
	if h1 != h2 {
		t.Errorf("hashes should be deterministic")
	}
	if len(h1) == 0 {
		t.Errorf("hash should not be empty")
	}
}
