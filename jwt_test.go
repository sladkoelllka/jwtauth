package jwtauth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
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

func TestGinMiddlewareStoresAuthInfo(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mgr := NewManager("secret")
	pair, err := mgr.GenerateTokenPair(42, map[string]interface{}{
		"role":            "owner",
		"organization_id": int32(7),
	})
	if err != nil {
		t.Fatal(err)
	}

	router := gin.New()
	router.Use(GinMiddleware(mgr, noopBlacklist{}))
	router.GET("/me", func(c *gin.Context) {
		userID, ok := UserIDFromGinContext(c)
		if !ok {
			t.Fatal("user id missing from gin context")
		}
		if userID != 42 {
			t.Fatalf("user id = %d, want 42", userID)
		}

		claims, ok := ClaimsFromGinContext(c)
		if !ok {
			t.Fatal("claims missing from gin context")
		}
		if claims["role"] != "owner" {
			t.Fatalf("role claim = %v, want owner", claims["role"])
		}
		if claims["organization_id"] != float64(7) {
			t.Fatalf("organization_id claim = %v, want 7", claims["organization_id"])
		}

		auth, ok := AuthInfoFromContext(c.Request.Context())
		if !ok {
			t.Fatal("auth info missing from request context")
		}
		if auth.UserID != 42 {
			t.Fatalf("request context user id = %d, want 42", auth.UserID)
		}

		c.Status(http.StatusNoContent)
	})

	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	req.Header.Set("Authorization", "Bearer "+pair.AccessToken)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusNoContent, rec.Body.String())
	}
}

type noopBlacklist struct{}

func (noopBlacklist) Exists(string) (bool, error) {
	return false, nil
}
