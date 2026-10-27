package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestProfileHandler(t *testing.T) {
	// 1. Không có Authorization header -> 401 Unauthorized
	t.Run("No token returns 401", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/auth/profile", nil)
		w := httptest.NewRecorder()
		profileHandler(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("Expected 401 Unauthorized, got %d", w.Code)
		}
	})

	// 2. Token không hợp lệ -> 401 Unauthorized
	t.Run("Invalid token returns 401", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/auth/profile", nil)
		req.Header.Set("Authorization", "Bearer invalid-token-xyz")
		w := httptest.NewRecorder()
		profileHandler(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("Expected 401 Unauthorized, got %d", w.Code)
		}
	})

	// 3. PUT với body rỗng / không có token -> 401 Unauthorized
	t.Run("PUT without token returns 401", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "/api/auth/profile", strings.NewReader(`{"full_name":"Test"}`))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		profileHandler(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("Expected 401 Unauthorized, got %d", w.Code)
		}
	})

	// 4. Method không hợp lệ (DELETE) -> 405 Method Not Allowed
	t.Run("DELETE method returns 405", func(t *testing.T) {
		token := createTestToken("user", "testuser")
		req := httptest.NewRequest(http.MethodDelete, "/api/auth/profile", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		profileHandler(w, req)

		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("Expected 405 Method Not Allowed, got %d", w.Code)
		}
	})
}
