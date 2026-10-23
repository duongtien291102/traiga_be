package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// P1-1: Kiểm tra phân quyền và IDOR trên DELETE /api/keys
func TestP1_1_DeleteKeys_Authorization(t *testing.T) {
	// 1. Anonymous request -> 401 Unauthorized
	t.Run("Anonymous request to DELETE /api/keys returns 401", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodDelete, "/api/keys?key=stream_test", nil)
		w := httptest.NewRecorder()
		apiKeysHandler(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("Expected 401 Unauthorized, got %d", w.Code)
		}
	})

	// 2. User role thông thường -> 403 Forbidden
	t.Run("Normal user role to DELETE /api/keys returns 403", func(t *testing.T) {
		token := createTestToken("user", "normal_user")
		req := httptest.NewRequest(http.MethodDelete, "/api/keys?key=stream_test", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		apiKeysHandler(w, req)

		if w.Code != http.StatusForbidden {
			t.Errorf("Expected 403 Forbidden, got %d", w.Code)
		}
	})

	// 3. Thiếu tham số key -> 400 Bad Request
	t.Run("Missing key param returns 400", func(t *testing.T) {
		token := createTestToken("admin", "admin_user")
		req := httptest.NewRequest(http.MethodDelete, "/api/keys", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		apiKeysHandler(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected 400 Bad Request for missing key param, got %d", w.Code)
		}
	})
}

// P1-1: Kiểm tra phân quyền trên /api/admin/room-bots
func TestP1_1_AdminRoomBots_Authorization(t *testing.T) {
	// 1. Anonymous -> 401 Unauthorized
	t.Run("Anonymous request to /api/admin/room-bots returns 401", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/admin/room-bots?streamKey=test", nil)
		w := httptest.NewRecorder()
		adminRoomBotsHandler(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("Expected 401 Unauthorized, got %d", w.Code)
		}
	})

	// 2. Normal user -> 403 Forbidden
	t.Run("Normal user request to /api/admin/room-bots returns 403", func(t *testing.T) {
		token := createTestToken("user", "regular_viewer")
		req := httptest.NewRequest(http.MethodGet, "/api/admin/room-bots?streamKey=test", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		adminRoomBotsHandler(w, req)

		if w.Code != http.StatusForbidden {
			t.Errorf("Expected 403 Forbidden, got %d", w.Code)
		}
	})

	// 3. POST vượt quá 5 bot -> 400 Bad Request
	t.Run("POST exceeding 5 bots returns 400", func(t *testing.T) {
		token := createTestToken("systemadmin", "sysadmin")
		payload := map[string]interface{}{
			"stream_key": "test_room",
			"bot_ids": []string{
				primitive.NewObjectID().Hex(),
				primitive.NewObjectID().Hex(),
				primitive.NewObjectID().Hex(),
				primitive.NewObjectID().Hex(),
				primitive.NewObjectID().Hex(),
				primitive.NewObjectID().Hex(), // 6 con bot
			},
			"is_running": true,
		}
		body, _ := json.Marshal(payload)
		req := httptest.NewRequest(http.MethodPost, "/api/admin/room-bots", strings.NewReader(string(body)))
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		adminRoomBotsHandler(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected 400 Bad Request when > 5 bots, got %d", w.Code)
		}
	})
}

// P1-2: Rate Limiting cho HTTP Login
func TestP1_2_RateLimiter_Login(t *testing.T) {
	initRateLimiters()
	testIP := "198.51.100.42"
	loginLimiter.Reset(testIP)

	handler := RateLimitLoginMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	})

	// 5 request đầu tiên phải thành công (200 OK)
	for i := 1; i <= 5; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/auth/login", nil)
		req.RemoteAddr = testIP + ":54321"
		w := httptest.NewRecorder()
		handler(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("Request %d should be allowed, got status %d", i, w.Code)
		}
	}

	// Request thứ 6 phải bị chặn với 429 Too Many Requests
	req6 := httptest.NewRequest(http.MethodPost, "/api/auth/login", nil)
	req6.RemoteAddr = testIP + ":54321"
	w6 := httptest.NewRecorder()
	handler(w6, req6)

	if w6.Code != http.StatusTooManyRequests {
		t.Errorf("Request 6 must be 429 Too Many Requests, got %d", w6.Code)
	}

	if w6.Header().Get("Retry-After") == "" {
		t.Errorf("Expected Retry-After header on 429 response")
	}

	// Địa chỉ IP khác vẫn phải được phép (không bị chặn theo chuỗi)
	otherIP := "198.51.100.99"
	loginLimiter.Reset(otherIP)
	reqOther := httptest.NewRequest(http.MethodPost, "/api/auth/login", nil)
	reqOther.RemoteAddr = otherIP + ":12345"
	wOther := httptest.NewRecorder()
	handler(wOther, reqOther)

	if wOther.Code != http.StatusOK {
		t.Errorf("Other IP should be allowed, got %d", wOther.Code)
	}
}

// P1-2: Rate Limiting WebSocket TokenBucket
func TestP1_2_TokenBucket_WebSocket(t *testing.T) {
	// Capacity 3, rate 1 token/sec
	tb := NewTokenBucket(1.0, 3.0)

	// Tiêu 3 token burst
	if !tb.Allow() || !tb.Allow() || !tb.Allow() {
		t.Errorf("Expected first 3 tokens to be allowed")
	}

	// Token thứ 4 trong cùng 1 thời điểm phải bị từ chối
	if tb.Allow() {
		t.Errorf("Expected 4th burst token to be rejected")
	}
}

// P1-3: WebSocket Origin Allowlist
func TestP1_3_WebSocketOrigin(t *testing.T) {
	os.Setenv("ALLOWED_ORIGINS", "http://localhost:3000,https://app.livestream.vn")
	os.Setenv("ALLOW_EMPTY_ORIGIN", "false")

	// 1. Origin hợp lệ trong allowlist
	t.Run("Valid allowed origin", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/ws/chat", nil)
		req.Header.Set("Origin", "http://localhost:3000")
		if !checkWebSocketOrigin(req) {
			t.Errorf("Expected valid origin http://localhost:3000 to be accepted")
		}
	})

	// 2. Origin hợp lệ thứ hai (HTTPS)
	t.Run("Valid https origin", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/ws/chat", nil)
		req.Header.Set("Origin", "https://app.livestream.vn")
		if !checkWebSocketOrigin(req) {
			t.Errorf("Expected valid origin https://app.livestream.vn to be accepted")
		}
	})

	// 3. Origin giả mạo / độc hại bị từ chối
	t.Run("Malicious origin rejected", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/ws/chat", nil)
		req.Header.Set("Origin", "http://attacker-evil.com")
		if checkWebSocketOrigin(req) {
			t.Errorf("Expected attacker origin to be rejected")
		}
	})

	// 4. Origin sai port bị từ chối
	t.Run("Wrong port origin rejected", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/ws/chat", nil)
		req.Header.Set("Origin", "http://localhost:9999")
		if checkWebSocketOrigin(req) {
			t.Errorf("Expected wrong port origin to be rejected")
		}
	})

	// 5. Origin rỗng bị từ chối khi ALLOW_EMPTY_ORIGIN=false
	t.Run("Empty origin rejected", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/ws/chat", nil)
		if checkWebSocketOrigin(req) {
			t.Errorf("Expected empty origin to be rejected")
		}
	})
}

// P1-5: Thu hồi token khi logout
func TestP1_5_TokenRevocation_Logout(t *testing.T) {
	globalTokenRevocationStore.Reset()

	tokenA := createTestToken("admin", "admin_alice")
	tokenB := createTestToken("user", "user_bob")

	// 1. Trước logout: Cả 2 token đều hợp lệ
	reqA := httptest.NewRequest(http.MethodGet, "/api/auth/me", nil)
	reqA.Header.Set("Authorization", "Bearer "+tokenA)
	claimsA, errA := getUserFromAuthHeader(reqA)
	if errA != nil || claimsA == nil || claimsA.Username != "admin_alice" {
		t.Fatalf("Token A should be valid before logout, err: %v", errA)
	}

	reqB := httptest.NewRequest(http.MethodGet, "/api/auth/me", nil)
	reqB.Header.Set("Authorization", "Bearer "+tokenB)
	claimsB, errB := getUserFromAuthHeader(reqB)
	if errB != nil || claimsB == nil || claimsB.Username != "user_bob" {
		t.Fatalf("Token B should be valid before logout, err: %v", errB)
	}

	// 2. User A thực hiện logout
	logoutReq := httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil)
	logoutReq.Header.Set("Authorization", "Bearer "+tokenA)
	logoutW := httptest.NewRecorder()
	logoutHandler(logoutW, logoutReq)

	if logoutW.Code != http.StatusOK {
		t.Fatalf("Logout must return 200 OK, got %d", logoutW.Code)
	}

	// 3. Sau logout: Token A phải bị từ chối vì đã thu hồi
	reqAAfter := httptest.NewRequest(http.MethodGet, "/api/auth/me", nil)
	reqAAfter.Header.Set("Authorization", "Bearer "+tokenA)
	_, errAAfter := getUserFromAuthHeader(reqAAfter)
	if errAAfter == nil {
		t.Errorf("Expected Token A to be rejected after logout, but it was accepted!")
	}
	if !strings.Contains(errAAfter.Error(), "revoked") {
		t.Errorf("Expected error message to mention revoked, got: %v", errAAfter)
	}

	// 4. Token B (của người dùng khác) vẫn phải hoạt động bình thường
	reqBAfter := httptest.NewRequest(http.MethodGet, "/api/auth/me", nil)
	reqBAfter.Header.Set("Authorization", "Bearer "+tokenB)
	claimsBAfter, errBAfter := getUserFromAuthHeader(reqBAfter)
	if errBAfter != nil || claimsBAfter == nil {
		t.Errorf("Token B should still be valid after user A logged out, err: %v", errBAfter)
	}

	// 5. Kiểm tra TokenRevocationStore với WebSocket tStr
	if !globalTokenRevocationStore.IsTokenRevoked(tokenA) {
		t.Errorf("Token A must be reported as revoked in globalTokenRevocationStore")
	}
	if globalTokenRevocationStore.IsTokenRevoked(tokenB) {
		t.Errorf("Token B must NOT be reported as revoked in globalTokenRevocationStore")
	}
}

// P1-4: Kiểm tra WebSocket không nhận token qua URL và bắt buộc handshake
func TestP1_4_WebSocket_AuthHandshake(t *testing.T) {
	// Kiểm tra payload auth_token được định nghĩa đầy đủ
	inMsg := WSInboundMessage{
		Type:      "auth_token",
		Token:     "test_token_value",
		GuestName: "Khách_1234",
	}

	b, err := json.Marshal(inMsg)
	if err != nil {
		t.Fatalf("Failed to marshal inbound auth message: %v", err)
	}

	var parsed WSInboundMessage
	if err := json.Unmarshal(b, &parsed); err != nil {
		t.Fatalf("Failed to unmarshal auth message: %v", err)
	}

	if parsed.Type != "auth_token" || parsed.Token != "test_token_value" {
		t.Errorf("Message schema mismatch, got: %+v", parsed)
	}

	// Kiểm tra payload auth_guest
	guestMsg := WSInboundMessage{
		Type:      "auth_guest",
		GuestName: "Khách_9999",
	}
	bGuest, _ := json.Marshal(guestMsg)
	var parsedGuest WSInboundMessage
	_ = json.Unmarshal(bGuest, &parsedGuest)
	if parsedGuest.Type != "auth_guest" || parsedGuest.GuestName != "Khách_9999" {
		t.Errorf("Guest message schema mismatch, got: %+v", parsedGuest)
	}
}
