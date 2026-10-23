package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

func TestAuthHandler(t *testing.T) {
	tests := []struct {
		name           string
		method         string
		streamKey      string
		expectedStatus int
	}{
		{
			name:           "Valid Key - test",
			method:         http.MethodPost,
			streamKey:      "test",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Valid Key - tiendev",
			method:         http.MethodPost,
			streamKey:      "tiendev",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Valid Key - supersecret",
			method:         http.MethodPost,
			streamKey:      "supersecret",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Invalid Key",
			method:         http.MethodPost,
			streamKey:      "hacker123",
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "Missing Key",
			method:         http.MethodPost,
			streamKey:      "",
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "Wrong HTTP Method (GET)",
			method:         http.MethodGet,
			streamKey:      "test",
			expectedStatus: http.StatusMethodNotAllowed,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			form := url.Values{}
			if tc.streamKey != "" {
				form.Set("name", tc.streamKey)
			}
			form.Set("app", "live")
			form.Set("addr", "127.0.0.1")

			req := httptest.NewRequest(tc.method, "/auth", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			w := httptest.NewRecorder()
			authHandler(w, req)

			resp := w.Result()
			if resp.StatusCode != tc.expectedStatus {
				t.Errorf("Expected status %d, got %d for case: %s", tc.expectedStatus, resp.StatusCode, tc.name)
			}
		})
	}
}

func TestUnpublishHandler(t *testing.T) {
	form := url.Values{}
	form.Set("name", "test")
	form.Set("app", "live")
	form.Set("addr", "127.0.0.1")

	req := httptest.NewRequest(http.MethodPost, "/auth/unpublish", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	w := httptest.NewRecorder()
	unpublishHandler(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected 200 OK for unpublish, got %d", resp.StatusCode)
	}
}

func init() {
	jwtSecret = []byte("super-secure-jwt-test-secret-key-at-least-32-chars!")
}

// helper tạo JWT token test
func createTestToken(role, username string) string {
	objID := primitive.NewObjectID()
	claims := JWTClaims{
		UserID:   objID.Hex(),
		Username: username,
		Role:     role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStr, _ := token.SignedString(jwtSecret)
	return tokenStr
}

// P0-1: Test bảo vệ endpoint GET /api/keys
func TestApiKeysHandler_Security(t *testing.T) {
	// 1. Anonymous request (không có token) -> Phải nhận 401 Unauthorized
	t.Run("Anonymous request must return 401", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/keys", nil)
		w := httptest.NewRecorder()
		apiKeysHandler(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("Expected 401 Unauthorized, got %d", w.Code)
		}
	})

	// 2. User role thông thường -> Phải nhận 403 Forbidden
	t.Run("Normal user role must return 403 Forbidden", func(t *testing.T) {
		token := createTestToken("user", "normaluser")
		req := httptest.NewRequest(http.MethodGet, "/api/keys", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		apiKeysHandler(w, req)

		if w.Code != http.StatusForbidden {
			t.Errorf("Expected 403 Forbidden, got %d", w.Code)
		}
	})

	// 3. Admin role -> Được phép truy cập (200 OK)
	t.Run("Admin role can access /api/keys", func(t *testing.T) {
		token := createTestToken("admin", "admin01")
		req := httptest.NewRequest(http.MethodGet, "/api/keys", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		apiKeysHandler(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected 200 OK for admin, got %d", w.Code)
		}
	})

	// 4. SystemAdmin role -> Được phép truy cập (200 OK)
	t.Run("SystemAdmin role can access /api/keys", func(t *testing.T) {
		token := createTestToken("systemadmin", "sysadmin")
		req := httptest.NewRequest(http.MethodGet, "/api/keys", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		apiKeysHandler(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected 200 OK for systemadmin, got %d", w.Code)
		}
	})
}

// P0-2: Test bảo vệ endpoint GET /api/sessions và che địa chỉ IP
func TestApiSessionsHandler_Security(t *testing.T) {
	// 1. Anonymous request -> Phải nhận 401 Unauthorized
	t.Run("Anonymous request to /api/sessions must return 401", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/sessions", nil)
		w := httptest.NewRecorder()
		apiSessionsHandler(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("Expected 401 Unauthorized, got %d", w.Code)
		}
	})

	// 2. User role thông thường -> Phải nhận 403 Forbidden
	t.Run("User role to /api/sessions must return 403", func(t *testing.T) {
		token := createTestToken("user", "normaluser")
		req := httptest.NewRequest(http.MethodGet, "/api/sessions", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		apiSessionsHandler(w, req)

		if w.Code != http.StatusForbidden {
			t.Errorf("Expected 403 Forbidden, got %d", w.Code)
		}
	})

	// 3. Admin role -> Được phép truy cập (200 OK)
	t.Run("Admin role can access /api/sessions", func(t *testing.T) {
		token := createTestToken("admin", "admin01")
		req := httptest.NewRequest(http.MethodGet, "/api/sessions", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		apiSessionsHandler(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected 200 OK for admin, got %d", w.Code)
		}
	})
}

// Test che địa chỉ IP streamer (maskIP)
func TestMaskIP(t *testing.T) {
	cases := []struct {
		input    string
		expected string
	}{
		{"103.21.244.55", "103.21.244.***"},
		{"192.168.1.1:8000", "192.168.1.***"},
		{"", "***"},
	}

	for _, tc := range cases {
		out := maskIP(tc.input)
		if out != tc.expected {
			t.Errorf("maskIP(%q) = %q, expected %q", tc.input, out, tc.expected)
		}
	}
}

// P0-3: Test sinh mật khẩu an toàn ngẫu nhiên
func TestGenerateSecureRandomPassword(t *testing.T) {
	pass1 := generateSecureRandomPassword(16)
	pass2 := generateSecureRandomPassword(16)

	if len(pass1) != 32 {
		t.Errorf("Expected 32 hex chars, got %d", len(pass1))
	}
	if pass1 == pass2 {
		t.Errorf("Generated passwords must be unique, got collision: %s", pass1)
	}
	if pass1 == "123456" {
		t.Errorf("Password must not be default 123456")
	}
}
