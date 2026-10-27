package chat

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo/options"

	"livestream-be/internal/model"
	"livestream-be/internal/security/limiter"
)

// Handler xử lý HTTP endpoints cho chat: nâng cấp WebSocket và lấy lịch sử tin nhắn.
type Handler struct {
	Hub         *Hub
	Service     *Service
	Upgrader    websocket.Upgrader
	GetClientIP func(r *http.Request) string
}

// NewHandler tạo mới Chat Handler.
func NewHandler(
	hub *Hub,
	service *Service,
	getClientIP func(r *http.Request) string,
) *Handler {
	return &Handler{
		Hub:         hub,
		Service:     service,
		Upgrader:    DefaultUpgrader,
		GetClientIP: getClientIP,
	}
}

// HandleWS nâng cấp kết nối HTTP lên WebSocket phòng chat.
// GET /ws/chat?streamKey=xxx
func (h *Handler) HandleWS(w http.ResponseWriter, r *http.Request) {
	streamKey := strings.TrimSpace(r.URL.Query().Get("streamKey"))
	if streamKey == "" {
		http.Error(w, "streamKey is required", http.StatusBadRequest)
		return
	}

	conn, err := h.Upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("❌ Lỗi nâng cấp WebSocket: %v", err)
		return
	}

	ip := ""
	if h.GetClientIP != nil {
		ip = h.GetClientIP(r)
	}

	client := &Client{
		Hub:           h.Hub,
		Conn:          conn,
		Send:          make(chan []byte, 128),
		StreamKey:     streamKey,
		Username:      "",
		Role:          "guest",
		ClientIP:      ip,
		Authenticated: false,
		RateLimiter:   limiter.NewTokenBucket(5.0, 10.0), // 5 msg/sec, burst 10
	}

	h.Hub.Register <- client

	go func() {
		time.Sleep(10 * time.Second)
		if !client.Authenticated {
			client.FallbackToGuest("", "Tự động kích hoạt chế độ Khách", h.Service)
		}
	}()

	go client.WritePump()
	go client.ReadPump(h.Service)
}

// HandleHistory trả về danh sách lịch sử tin nhắn của phòng live.
// GET /api/chat/history?streamKey=xxx
// GET /api/chat/history?streamKey=xxx&sessionId=yyy
func (h *Handler) HandleHistory(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	streamKey := strings.TrimSpace(r.URL.Query().Get("streamKey"))
	if streamKey == "" {
		http.Error(w, `{"error":"streamKey is required"}`, http.StatusBadRequest)
		return
	}

	sessionID := strings.TrimSpace(r.URL.Query().Get("sessionId"))
	canViewPhones := h.Service.RequestCanViewRoomPhones(r, streamKey)

	st := h.Service.GetStore()
	if sessionID != "" && st != nil && st.Chat != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		opts := options.Find().SetSort(bson.M{"created_at": 1}).SetLimit(500)
		filter := bson.M{"stream_key": streamKey, "session_id": sessionID}
		cursor, err := st.Chat.Find(ctx, filter, opts)
		if err == nil {
			defer cursor.Close(ctx)
			msgs := make([]model.ChatMessage, 0)
			_ = cursor.All(ctx, &msgs)
			for i := range msgs {
				if msgs[i].Username == "sysadmin" || msgs[i].Role == "systemadmin" {
					msgs[i].Username = "Ban Quản Trị"
				} else if msgs[i].Username == "admin01" {
					msgs[i].Username = "Chủ Trại"
				}
			}
			msgs = SanitizeChatHistory(msgs, canViewPhones)
			_ = json.NewEncoder(w).Encode(msgs)
			return
		}
	}

	history := h.Service.GetRecentChatHistory(streamKey)
	history = SanitizeChatHistory(history, canViewPhones)
	_ = json.NewEncoder(w).Encode(history)
}
