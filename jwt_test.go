package jwtauth

import (
	"errors"
	"testing"
	"time"
)

func TestAccessTokenGenerationValidation(t *testing.T) {
	mgr := NewManager(Options{
		Secret:    "secret",
		AccessTTL: time.Minute,
		Issuer:    "test-service",
		Audience:  []string{"mobile"},
	})

	before := time.Now().Unix()
	token, err := mgr.GenerateAccessToken(123, AccessTokenOptions{
		SessionID: "session-1",
		Extra: map[string]interface{}{
			"role": "user",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	after := time.Now().Unix()

	claims, err := mgr.ValidateAccessTokenDetailed(token)
	if err != nil {
		t.Fatalf("access validation failed: %v", err)
	}
	if claims.UserID != 123 {
		t.Fatalf("expected uid 123 got %d", claims.UserID)
	}
	if claims.SessionID != "session-1" {
		t.Fatalf("expected session id")
	}
	if claims.IssuedAt < before || claims.IssuedAt > after {
		t.Fatalf("unexpected iat: %d", claims.IssuedAt)
	}
	if claims.ExpiresAt == 0 {
		t.Fatalf("expected exp")
	}
	if claims.Issuer != "test-service" {
		t.Fatalf("expected issuer")
	}
	if len(claims.Audience) != 1 || claims.Audience[0] != "mobile" {
		t.Fatalf("expected audience")
	}
	if claims.Extra["role"] != "user" {
		t.Fatalf("extra claim missing")
	}
}

func TestAccessTokenRejectsReservedClaims(t *testing.T) {
	mgr := NewManager(Options{Secret: "secret"})

	_, err := mgr.GenerateAccessToken(123, AccessTokenOptions{
		Extra: map[string]interface{}{
			"exp": "override",
		},
	})
	if err == nil {
		t.Fatal("expected reserved claim error")
	}
}

func TestOpaqueRefreshToken(t *testing.T) {
	t1, err := GenerateOpaqueRefreshToken()
	if err != nil {
		t.Fatal(err)
	}
	t2, err := GenerateOpaqueRefreshToken()
	if err != nil {
		t.Fatal(err)
	}
	if t1 == "" || t2 == "" {
		t.Fatal("expected non-empty tokens")
	}
	if t1 == t2 {
		t.Fatal("expected unique tokens")
	}
	if HashToken(t1) == t1 {
		t.Fatal("hash must not equal raw token")
	}
}

func TestValidateAccessTokenWrongIssuer(t *testing.T) {
	issuerA := NewManager(Options{Secret: "secret", Issuer: "a"})
	issuerB := NewManager(Options{Secret: "secret", Issuer: "b"})

	token, err := issuerA.GenerateAccessToken(123, AccessTokenOptions{})
	if err != nil {
		t.Fatal(err)
	}

	_, err = issuerB.ValidateAccessTokenDetailed(token)
	if !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken, got %v", err)
	}
}

func TestExtractBearerToken(t *testing.T) {
	token, err := ExtractBearerToken("Bearer abc")
	if err != nil {
		t.Fatal(err)
	}
	if token != "abc" {
		t.Fatalf("expected abc got %q", token)
	}

	if _, err := ExtractBearerToken("Basic abc"); !errors.Is(err, ErrInvalidBearerToken) {
		t.Fatalf("expected ErrInvalidBearerToken, got %v", err)
	}
	if _, err := ExtractBearerToken("Bearer"); !errors.Is(err, ErrInvalidBearerToken) {
		t.Fatalf("expected ErrInvalidBearerToken, got %v", err)
	}
}
