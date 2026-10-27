package chicken

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"livestream-be/internal/model"
)

func TestChickenHandler_Get(t *testing.T) {
	h := NewHandler(nil, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/chickens", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", w.Code)
	}

	var list []model.Chicken
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil {
		t.Fatalf("response must be valid JSON array: %v", err)
	}
	if len(list) != 0 {
		t.Fatalf("expected empty list, got %d items", len(list))
	}
}

func TestChickenHandler_PostAuth(t *testing.T) {
	t.Run("anonymous returns 401", func(t *testing.T) {
		h := NewHandler(nil, nil, nil)
		req := httptest.NewRequest(http.MethodPost, "/api/chickens", strings.NewReader(`{"title":"Gà Chọi"}`))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 Unauthorized, got %d", w.Code)
		}
	})

	t.Run("non-admin returns 403", func(t *testing.T) {
		mockGetUser := func(r *http.Request) (*model.JWTClaims, error) {
			return &model.JWTClaims{
				Username: "user1",
				Role:     "user",
			}, nil
		}
		h := NewHandler(nil, mockGetUser, nil)
		req := httptest.NewRequest(http.MethodPost, "/api/chickens", strings.NewReader(`{"title":"Gà Chọi"}`))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)

		if w.Code != http.StatusForbidden {
			t.Fatalf("expected 403 Forbidden, got %d", w.Code)
		}
	})

	t.Run("empty title returns 400", func(t *testing.T) {
		mockGetUser := func(r *http.Request) (*model.JWTClaims, error) {
			return &model.JWTClaims{
				Username: "admin01",
				Role:     "admin",
			}, nil
		}
		h := NewHandler(nil, mockGetUser, nil)
		req := httptest.NewRequest(http.MethodPost, "/api/chickens", strings.NewReader(`{"title":"   "}`))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 Bad Request for empty title, got %d", w.Code)
		}
	})
}

func TestChickenHandler_MethodNotAllowed(t *testing.T) {
	h := NewHandler(nil, nil, nil)
	req := httptest.NewRequest(http.MethodPut, "/api/chickens", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 Method Not Allowed, got %d", w.Code)
	}
}
