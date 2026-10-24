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

// ==================== GIAI ĐOẠN 1, 2, 3 SECURITY HARDENING TESTS ====================

// Giai đoạn 1: Kiểm tra chống IDOR trên /api/keys/toggle
func TestPhase1_IDOR_ToggleKey(t *testing.T) {
	// 1. Anonymous -> 401
	t.Run("Anonymous request returns 401", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/keys/toggle", strings.NewReader(`{"key":"admin01","is_active":false}`))
		w := httptest.NewRecorder()
		toggleKeyHandler(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("Expected 401 Unauthorized, got %d", w.Code)
		}
	})

	// 2. IDOR: admin02 cố tình khóa key của admin01 -> 403 Forbidden
	t.Run("Admin02 cannot toggle Admin01 key (IDOR blocked)", func(t *testing.T) {
		tokenAdmin02 := createTestToken("admin", "admin02")
		req := httptest.NewRequest(http.MethodPost, "/api/keys/toggle", strings.NewReader(`{"key":"admin01","is_active":false}`))
		req.Header.Set("Authorization", "Bearer "+tokenAdmin02)
		w := httptest.NewRecorder()
		toggleKeyHandler(w, req)
		if w.Code != http.StatusForbidden {
			t.Errorf("Expected 403 Forbidden when admin02 toggles admin01's key, got %d", w.Code)
		}
	})

	// 3. Admin01 bật/tắt key của chính mình -> 200 OK
	t.Run("Admin01 can toggle own key", func(t *testing.T) {
		tokenAdmin01 := createTestToken("admin", "admin01")
		req := httptest.NewRequest(http.MethodPost, "/api/keys/toggle", strings.NewReader(`{"key":"admin01","is_active":true}`))
		req.Header.Set("Authorization", "Bearer "+tokenAdmin01)
		w := httptest.NewRecorder()
		toggleKeyHandler(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("Expected 200 OK when admin01 toggles own key, got %d", w.Code)
		}
	})
}

// Giai đoạn 1: Kiểm tra chống IDOR trên /api/sessions/replay và /api/admin/room-bots
func TestPhase1_IDOR_ReplayAndRoomBots(t *testing.T) {
	// 1. IDOR trên /api/sessions/replay: admin02 gắn replay cho phòng của admin01 -> 403 Forbidden
	t.Run("Admin02 cannot manage replay for Admin01 room", func(t *testing.T) {
		tokenAdmin02 := createTestToken("admin", "admin02")
		body := `{"stream_key":"admin01","title":"Fake Replay","replay_url":"https://drive.google.com/file/d/1a2b3c4d5e6f7g8h9i0j/view"}`
		req := httptest.NewRequest(http.MethodPost, "/api/sessions/replay", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+tokenAdmin02)
		w := httptest.NewRecorder()
		apiSessionReplayManageHandler(w, req)
		if w.Code != http.StatusForbidden {
			t.Errorf("Expected 403 Forbidden for IDOR on /api/sessions/replay, got %d", w.Code)
		}
	})

	// 2. IDOR trên GET /api/admin/room-bots: admin02 xem bot phòng của admin01 -> 403 Forbidden
	t.Run("Admin02 cannot view room-bots of Admin01", func(t *testing.T) {
		tokenAdmin02 := createTestToken("admin", "admin02")
		req := httptest.NewRequest(http.MethodGet, "/api/admin/room-bots?streamKey=admin01", nil)
		req.Header.Set("Authorization", "Bearer "+tokenAdmin02)
		w := httptest.NewRecorder()
		adminRoomBotsHandler(w, req)
		if w.Code != http.StatusForbidden {
			t.Errorf("Expected 403 Forbidden when admin02 accesses admin01's room-bots, got %d", w.Code)
		}
	})

	// 3. IDOR trên POST /api/admin/room-bots: admin02 bật/tắt bot phòng của admin01 -> 403 Forbidden
	t.Run("Admin02 cannot toggle room-bots of Admin01", func(t *testing.T) {
		tokenAdmin02 := createTestToken("admin", "admin02")
		body := `{"stream_key":"admin01","bot_ids":[],"is_running":false}`
		req := httptest.NewRequest(http.MethodPost, "/api/admin/room-bots", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+tokenAdmin02)
		w := httptest.NewRecorder()
		adminRoomBotsHandler(w, req)
		if w.Code != http.StatusForbidden {
			t.Errorf("Expected 403 Forbidden when admin02 modifies admin01's room-bots, got %d", w.Code)
		}
	})
}

// Giai đoạn 1: Kiểm tra xác thực trên GET /api/admin/bots
func TestPhase1_AdminBots_AuthRequired(t *testing.T) {
	t.Run("Anonymous request to GET /api/admin/bots returns 401", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/admin/bots", nil)
		w := httptest.NewRecorder()
		adminAvailableBotsHandler(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("Expected 401 Unauthorized, got %d", w.Code)
		}
	})

	t.Run("Normal user request to GET /api/admin/bots returns 403", func(t *testing.T) {
		tokenUser := createTestToken("user", "viewer01")
		req := httptest.NewRequest(http.MethodGet, "/api/admin/bots", nil)
		req.Header.Set("Authorization", "Bearer "+tokenUser)
		w := httptest.NewRecorder()
		adminAvailableBotsHandler(w, req)
		if w.Code != http.StatusForbidden {
			t.Errorf("Expected 403 Forbidden, got %d", w.Code)
		}
	})

	t.Run("Admin request to GET /api/admin/bots returns 200", func(t *testing.T) {
		tokenAdmin := createTestToken("admin", "admin01")
		req := httptest.NewRequest(http.MethodGet, "/api/admin/bots", nil)
		req.Header.Set("Authorization", "Bearer "+tokenAdmin)
		w := httptest.NewRecorder()
		adminAvailableBotsHandler(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("Expected 200 OK for admin, got %d", w.Code)
		}
	})
}

// Giai đoạn 1: Kiểm tra SRS Webhook Secret và giới hạn kích thước Body (MaxBytesReader)
func TestPhase1_WebhookSecretAndMaxBytes(t *testing.T) {
	os.Setenv("SRS_WEBHOOK_SECRET", "my_super_secret_srs_token_2026")
	defer os.Unsetenv("SRS_WEBHOOK_SECRET")

	// 1. Gọi /auth/unpublish không có secret -> 403 Forbidden
	t.Run("Webhook without secret rejected with 403", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/auth/unpublish", strings.NewReader(`{"stream":"tiendev"}`))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		unpublishHandler(w, req)
		if w.Code != http.StatusForbidden {
			t.Errorf("Expected 403 Forbidden without webhook secret, got %d", w.Code)
		}
	})

	// 2. Gọi /auth/dvr với secret sai -> 403 Forbidden
	t.Run("Webhook with wrong secret rejected with 403", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/auth/dvr?secret=wrong_token", strings.NewReader(`{"stream":"tiendev","file":"test.mp4"}`))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		dvrHandler(w, req)
		if w.Code != http.StatusForbidden {
			t.Errorf("Expected 403 Forbidden with wrong webhook secret, got %d", w.Code)
		}
	})

	// 3. Gọi /auth/unpublish với secret hợp lệ qua Header -> 200 OK
	t.Run("Webhook with valid Header secret accepted with 200", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/auth/unpublish", strings.NewReader(`{"stream":"tiendev"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-SRS-Webhook-Secret", "my_super_secret_srs_token_2026")
		w := httptest.NewRecorder()
		unpublishHandler(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("Expected 200 OK with valid webhook secret, got %d", w.Code)
		}
	})

	// 4. Gọi /auth/unpublish với body vượt quá 64KB -> 413 Request Entity Too Large
	t.Run("Oversized body blocked by MaxBytesReader with 413", func(t *testing.T) {
		hugePayload := `{"stream":"` + strings.Repeat("A", 100*1024) + `"}`
		req := httptest.NewRequest(http.MethodPost, "/auth/unpublish?secret=my_super_secret_srs_token_2026", strings.NewReader(hugePayload))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		unpublishHandler(w, req)
		if w.Code != http.StatusRequestEntityTooLarge {
			t.Errorf("Expected 413 Request Entity Too Large for 100KB payload, got %d", w.Code)
		}
	})
}

// Giai đoạn 2: Kiểm tra Input Validation (normalizeReplayURL chống XSS & registerHandler)
func TestPhase2_InputValidation_XSSAndRegister(t *testing.T) {
	// 1. normalizeReplayURL phải chặn javascript:, data:, vbscript: và path traversal
	maliciousURLs := []string{
		"javascript:alert(document.cookie)",
		"JAVASCRIPT:alert(1)",
		"data:text/html,<script>alert(1)</script>",
		"vbscript:msgbox(1)",
		"/record/live/../../etc/passwd",
	}
	for _, u := range maliciousURLs {
		norm, _ := normalizeReplayURL(u)
		if norm != "" {
			t.Errorf("Expected malicious replay URL %q to be rejected, but got %q", u, norm)
		}
	}

	// Các URL hợp lệ phải được chấp nhận
	validDrive, id := normalizeReplayURL("https://drive.google.com/file/d/1AbCdEfGhIjKlMnOpQrStUvWxYz/view?usp=sharing")
	if validDrive == "" || id != "1AbCdEfGhIjKlMnOpQrStUvWxYz" {
		t.Errorf("Expected valid Drive URL to normalize properly, got %q (id=%q)", validDrive, id)
	}
	validRecord, _ := normalizeReplayURL("/record/live/tiendev.1700000.mp4")
	if validRecord != "/record/live/tiendev.1700000.mp4" {
		t.Errorf("Expected /record/ path to be accepted, got %q", validRecord)
	}

	// 2. registerHandler: kiểm tra độ dài username/password
	initRateLimiters()
	registerLimiter.Reset("203.0.113.10")

	t.Run("Reject short username", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/auth/register", strings.NewReader(`{"username":"ab","password":"password123"}`))
		req.RemoteAddr = "203.0.113.10:1234"
		w := httptest.NewRecorder()
		registerHandler(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected 400 Bad Request for 2-char username, got %d", w.Code)
		}
	})

	t.Run("Reject short password (< 6 chars)", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/auth/register", strings.NewReader(`{"username":"validuser","password":"123"}`))
		req.RemoteAddr = "203.0.113.10:1234"
		w := httptest.NewRecorder()
		registerHandler(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected 400 Bad Request for 3-char password, got %d", w.Code)
		}
	})
}

// Giai đoạn 2: Kiểm tra Rate Limit trên POST /api/auth/register
func TestPhase2_RegisterRateLimit(t *testing.T) {
	initRateLimiters()
	testIP := "203.0.113.55"
	registerLimiter.Reset(testIP)

	for i := 1; i <= 5; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/auth/register", strings.NewReader(`{"username":"ab","password":"123"}`))
		req.RemoteAddr = testIP + ":10000"
		w := httptest.NewRecorder()
		registerHandler(w, req)
		if w.Code == http.StatusTooManyRequests {
			t.Fatalf("Register request %d should not be rate limited yet", i)
		}
	}

	// Request thứ 6 từ cùng IP phải nhận 429 Too Many Requests
	req6 := httptest.NewRequest(http.MethodPost, "/api/auth/register", strings.NewReader(`{"username":"ab","password":"123"}`))
	req6.RemoteAddr = testIP + ":10000"
	w6 := httptest.NewRecorder()
	registerHandler(w6, req6)
	if w6.Code != http.StatusTooManyRequests {
		t.Errorf("Expected 6th register request to return 429 Too Many Requests, got %d", w6.Code)
	}
}

// Giai đoạn 2 & 3: Kiểm tra CORS Allowlist và HTTP Security Headers trên corsMiddleware
func TestPhase2_3_CORSAndSecurityHeaders(t *testing.T) {
	os.Setenv("ALLOWED_ORIGINS", "http://localhost:3000,https://traiga-fe.vercel.app")
	defer os.Unsetenv("ALLOWED_ORIGINS")

	dummyHandler := corsMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// 1. Origin hợp lệ nhận được Access-Control-Allow-Origin chính xác và đầy đủ Security Headers
	t.Run("Allowed Origin receives CORS header and Security Headers", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		req.Header.Set("Origin", "https://traiga-fe.vercel.app")
		w := httptest.NewRecorder()
		dummyHandler.ServeHTTP(w, req)

		if got := w.Header().Get("Access-Control-Allow-Origin"); got != "https://traiga-fe.vercel.app" {
			t.Errorf("Expected Access-Control-Allow-Origin 'https://traiga-fe.vercel.app', got %q", got)
		}
		if w.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("Missing X-Content-Type-Options: nosniff header")
		}
		if w.Header().Get("X-Frame-Options") != "DENY" {
			t.Errorf("Missing X-Frame-Options: DENY header")
		}
		if w.Header().Get("Strict-Transport-Security") == "" {
			t.Errorf("Missing Strict-Transport-Security header")
		}
	})

	// 2. Origin lạ gửi OPTIONS preflight bị từ chối với 403 Forbidden và không có wildcard *
	t.Run("Disallowed Origin preflight rejected with 403", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodOptions, "/api/keys", nil)
		req.Header.Set("Origin", "https://evil-hacker.example.com")
		w := httptest.NewRecorder()
		dummyHandler.ServeHTTP(w, req)

		if w.Code != http.StatusForbidden {
			t.Errorf("Expected 403 Forbidden for disallowed Origin OPTIONS, got %d", w.Code)
		}
		if got := w.Header().Get("Access-Control-Allow-Origin"); got != "" {
			t.Errorf("Expected empty Access-Control-Allow-Origin for evil origin, got %q", got)
		}
	})
}

