package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// TestRoomIsolation kiểm tra đảm bảo 100% tin nhắn giữa các phòng không bao giờ bị lẫn lộn
func TestRoomIsolation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(wsChatHandler))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	originHeader := http.Header{"Origin": []string{"http://localhost:3000"}}

	// 1. Client A vào phòng 'tiendev'
	urlA := wsURL + "/ws/chat?streamKey=tiendev"
	connA, _, err := websocket.DefaultDialer.Dial(urlA, originHeader)
	if err != nil {
		t.Fatalf("Client A kết nối thất bại: %v", err)
	}
	defer connA.Close()

	// Handshake xác thực cho Client A
	authA, _ := json.Marshal(WSInboundMessage{Type: "auth_guest", GuestName: "User_A"})
	_ = connA.WriteMessage(websocket.TextMessage, authA)

	// 2. Client B vào phòng 'test'
	urlB := wsURL + "/ws/chat?streamKey=test"
	connB, _, err := websocket.DefaultDialer.Dial(urlB, originHeader)
	if err != nil {
		t.Fatalf("Client B kết nối thất bại: %v", err)
	}
	defer connB.Close()

	// Handshake xác thực cho Client B
	authB, _ := json.Marshal(WSInboundMessage{Type: "auth_guest", GuestName: "User_B"})
	_ = connB.WriteMessage(websocket.TextMessage, authB)

	// Đọc các message khởi tạo (viewer_count, auth_login_result, history) của mỗi client
	for i := 0; i < 3; i++ {
		connA.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, _, _ = connA.ReadMessage()

		connB.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, _, _ = connB.ReadMessage()
	}

	// 3. Client A gửi tin nhắn vào phòng 'tiendev'
	msgA := WSInboundMessage{
		Type:    "chat",
		Message: "Tin nhắn phòng tiendev",
	}
	msgABytes, _ := json.Marshal(msgA)
	if err := connA.WriteMessage(websocket.TextMessage, msgABytes); err != nil {
		t.Fatalf("Client A gửi tin thất bại: %v", err)
	}

	// 4. Client A PHẢI nhận được tin nhắn trong phòng 'tiendev'
	connA.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, pA, err := connA.ReadMessage()
	if err != nil {
		t.Fatalf("Client A không nhận được tin nhắn broadcast: %v", err)
	}
	var receivedA WSOutboundMessage
	if err := json.Unmarshal(pA, &receivedA); err != nil || receivedA.Data == nil || receivedA.Data.Message != msgA.Message {
		t.Fatalf("Nội dung tin nhắn không khớp: %s", string(pA))
	}
	if receivedA.Data.StreamKey != "tiendev" {
		t.Fatalf("StreamKey tin nhắn không đúng: %s", receivedA.Data.StreamKey)
	}

	// 5. Client B ở phòng 'test' KHÔNG ĐƯỢC NHẬN tin nhắn của phòng 'tiendev'
	connB.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
	_, pB, err := connB.ReadMessage()
	if err == nil {
		var receivedB WSOutboundMessage
		if json.Unmarshal(pB, &receivedB) == nil && receivedB.Type == "chat" {
			t.Fatalf("❌ LỖI RÒ RỈ: Phòng 'test' nhận nhầm tin nhắn của phòng 'tiendev': %s", string(pB))
		}
	}

	t.Log("✅ Kênh chat của các phòng hoạt động hoàn toàn độc lập, không bị lẫn lộn!")
}

