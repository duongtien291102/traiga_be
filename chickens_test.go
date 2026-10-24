package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

func TestChickens_API(t *testing.T) {
	// 1. GET /api/chickens khi chưa có dữ liệu phải trả về 200 và mảng rỗng []
	t.Run("GET /api/chickens public returns 200", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/chickens", nil)
		w := httptest.NewRecorder()
		apiChickensHandler(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected 200 OK for GET /api/chickens, got %d", w.Code)
		}
		var list []Chicken
		if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil {
			t.Errorf("Response must be valid JSON array: %v", err)
		}
	})

	// 2. POST /api/chickens không có token -> 401 Unauthorized
	t.Run("POST /api/chickens anonymous returns 401", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/chickens", strings.NewReader(`{"title":"Gà Chọi Tía"}`))
		w := httptest.NewRecorder()
		apiChickensHandler(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("Expected 401 Unauthorized, got %d", w.Code)
		}
	})

	// 3. POST /api/chickens với role user bình thường -> 403 Forbidden
	t.Run("POST /api/chickens normal user returns 403", func(t *testing.T) {
		token, err := createToken(User{
			ID:       primitive.NewObjectID(),
			Username: "viewer1",
			Role:     "user",
		})
		if err != nil {
			t.Fatalf("Failed to create token: %v", err)
		}

		req := httptest.NewRequest(http.MethodPost, "/api/chickens", strings.NewReader(`{"title":"Gà Chọi Tía"}`))
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		apiChickensHandler(w, req)

		if w.Code != http.StatusForbidden {
			t.Errorf("Expected 403 Forbidden for normal user, got %d", w.Code)
		}
	})

	// 4. GET /api/rooms public trả về 200
	t.Run("GET /api/rooms public returns 200", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/rooms", nil)
		w := httptest.NewRecorder()
		apiPublicRoomsHandler(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected 200 OK for GET /api/rooms, got %d", w.Code)
		}
	})
}

func TestCleanMockBots(t *testing.T) {
	// Kiểm tra hàm cleanMockBots chạy an toàn không gây panic
	cleanMockBots()
	t.Log("✅ cleanMockBots chạy thành công")
}
