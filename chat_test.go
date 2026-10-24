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

// TestChatResetBroadcastAndOfflineHistory kiểm tra cơ chế reset chat và ẩn tin nhắn khi luồng offline
func TestChatResetBroadcastAndOfflineHistory(t *testing.T) {
	// 1. Kiểm tra getRecentChatHistory trên phòng offline hoặc chưa live -> phải trả về rỗng []
	historyOffline := getRecentChatHistory("offline_room_test")
	if len(historyOffline) != 0 {
		t.Errorf("Phòng offline không được trả về lịch sử chat cũ, mong muốn 0 tin nhắn nhưng nhận %d", len(historyOffline))
	}

	// 2. Kiểm tra broadcastResetChat phát sự kiện reset_chat tới đúng client trong phòng
	server := httptest.NewServer(http.HandlerFunc(wsChatHandler))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	originHeader := http.Header{"Origin": []string{"http://localhost:3000"}}

	urlA := wsURL + "/ws/chat?streamKey=reset_room"
	connA, _, err := websocket.DefaultDialer.Dial(urlA, originHeader)
	if err != nil {
		t.Fatalf("Client A kết nối thất bại: %v", err)
	}
	defer connA.Close()

	authA, _ := json.Marshal(WSInboundMessage{Type: "auth_guest", GuestName: "Viewer_1"})
	_ = connA.WriteMessage(websocket.TextMessage, authA)

	// Đọc các message khởi tạo
	for i := 0; i < 3; i++ {
		connA.SetReadDeadline(time.Now().Add(1 * time.Second))
		_, _, _ = connA.ReadMessage()
	}

	// Phát lệnh reset kênh chat
	broadcastResetChat("reset_room")

	// Client A phải nhận được sự kiện type "reset_chat"
	connA.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, pReset, err := connA.ReadMessage()
	if err != nil {
		t.Fatalf("Client không nhận được thông báo reset_chat: %v", err)
	}

	var resetMsg WSOutboundMessage
	if err := json.Unmarshal(pReset, &resetMsg); err != nil {
		t.Fatalf("Lỗi parse reset_chat: %v", err)
	}
	if resetMsg.Type != "reset_chat" {
		t.Fatalf("Loại tin nhắn mong muốn là 'reset_chat', nhận được: %s", resetMsg.Type)
	}

	t.Log("✅ Sự kiện reset_chat được phát thành công và lịch sử offline bị ẩn hoàn toàn!")
}

