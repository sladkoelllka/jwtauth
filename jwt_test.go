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
