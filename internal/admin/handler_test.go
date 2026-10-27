package admin_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.mongodb.org/mongo-driver/bson/primitive"

	"livestream-be/internal/admin"
	"livestream-be/internal/model"
	"livestream-be/internal/store"
)

var testJWTSecret = []byte("super-secure-jwt-test-secret-key-at-least-32-chars!")

func createTestToken(role, username string) string {
	objID := primitive.NewObjectID()
	claims := model.JWTClaims{
		UserID:   objID.Hex(),
		Username: username,
		Role:     role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStr, _ := token.SignedString(testJWTSecret)
	return tokenStr
}

func setupTestHandler() *admin.Handler {
	return admin.NewHandler(
		func() *store.Store { return nil },
		func() []byte { return testJWTSecret },
	)
}

func TestLogs_Auth(t *testing.T) {
	h := setupTestHandler()

	t.Run("Anonymous request returns 403", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/sysadmin/logs", nil)
		w := httptest.NewRecorder()
		h.Logs(w, req)

		if w.Code != http.StatusForbidden {
			t.Errorf("expected 403 Forbidden, got %d", w.Code)
		}
	})

	t.Run("User role returns 403", func(t *testing.T) {
		token := createTestToken("user", "testuser")
		req := httptest.NewRequest(http.MethodGet, "/api/sysadmin/logs", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		h.Logs(w, req)

		if w.Code != http.StatusForbidden {
			t.Errorf("expected 403 Forbidden, got %d", w.Code)
		}
	})

	t.Run("Admin role returns 403", func(t *testing.T) {
		token := createTestToken("admin", "admin01")
		req := httptest.NewRequest(http.MethodGet, "/api/sysadmin/logs", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		h.Logs(w, req)

		if w.Code != http.StatusForbidden {
			t.Errorf("expected 403 Forbidden for admin role, got %d", w.Code)
		}
	})
}

func TestLiveStats_Auth(t *testing.T) {
	h := setupTestHandler()

	t.Run("Anonymous request returns 403", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/sysadmin/live-stats", nil)
		w := httptest.NewRecorder()
		h.LiveStats(w, req)

		if w.Code != http.StatusForbidden {
			t.Errorf("expected 403 Forbidden, got %d", w.Code)
		}
	})

	t.Run("User role returns 403", func(t *testing.T) {
		token := createTestToken("user", "testuser")
		req := httptest.NewRequest(http.MethodGet, "/api/sysadmin/live-stats", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		h.LiveStats(w, req)

		if w.Code != http.StatusForbidden {
			t.Errorf("expected 403 Forbidden, got %d", w.Code)
		}
	})
}
