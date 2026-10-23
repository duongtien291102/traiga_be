package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

// ChatMessage đại diện cho 1 tin nhắn trong phòng live
type ChatMessage struct {
	ID        primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	StreamKey string             `bson:"stream_key" json:"stream_key"`
	Username  string             `bson:"username" json:"username"`
	Role      string             `bson:"role" json:"role"` // "admin" | "streamer" | "user" | "guest"
	Message   string             `bson:"message" json:"message"`
	Type      string             `bson:"type" json:"type"` // "chat" | "system" | "reaction"
	CreatedAt time.Time          `bson:"created_at" json:"created_at"`
}

// WSInboundMessage payload gửi từ client lên server
type WSInboundMessage struct {
	Type      string `json:"type"`                 // "chat" | "reaction" | "auth_login" | "auth_token" | "auth_guest"
	Message   string `json:"message"`              // Nội dung tin nhắn
	Emoji     string `json:"emoji,omitempty"`      // Icon reaction (nếu type == "reaction")
	Username  string `json:"username,omitempty"`   // Tên đăng nhập (nếu type == "auth_login")
	Password  string `json:"password,omitempty"`   // Mật khẩu (nếu type == "auth_login")
	Token     string `json:"token,omitempty"`      // JWT Token xác thực socket
	Role      string `json:"role,omitempty"`       // Role gửi kèm (nếu có)
	Sender    string `json:"sender,omitempty"`     // Tên người gửi (nếu có)
	GuestName string `json:"guest_name,omitempty"` // Tên khách (nếu type == "auth_guest")
}

// WSOutboundMessage payload server broadcast tới các client
type WSOutboundMessage struct {
	Type        string        `json:"type"`                  // "chat" | "system" | "viewer_count" | "reaction" | "history" | "auth_login_result" | "error"
	Data        *ChatMessage  `json:"data,omitempty"`        // Tin nhắn đơn
	ViewerCount int           `json:"viewer_count,omitempty"` // Số người đang xem
	Emoji       string        `json:"emoji,omitempty"`       // Icon thả tim
	Sender      string        `json:"sender,omitempty"`      // Người gửi reaction
	History     []ChatMessage `json:"history,omitempty"`     // Lịch sử tin nhắn gần đây
	Success     bool          `json:"success,omitempty"`     // Cho auth_login_result
	Error       string        `json:"error,omitempty"`       // Cho auth_login_result hoặc error
	Token       string        `json:"token,omitempty"`       // Cho auth_login_result
	User        *User         `json:"user,omitempty"`        // Cho auth_login_result
	StreamKey   string        `json:"stream_key,omitempty"`  // Cho auth_login_result
	StreamKeys  []StreamKey   `json:"stream_keys,omitempty"` // Cho auth_login_result
}

// checkWebSocketOrigin kiểm tra Origin của request theo allowlist cấu hình
func checkWebSocketOrigin(r *http.Request) bool {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		if os.Getenv("ALLOW_EMPTY_ORIGIN") == "true" {
			return true
		}
		log.Printf("⛔ [WS REJECT] Thiếu Header Origin từ %s", r.RemoteAddr)
		return false
	}

	parsedOrigin, err := url.Parse(origin)
	if err != nil || parsedOrigin.Host == "" {
		log.Printf("⛔ [WS REJECT] Origin không hợp lệ: %s", origin)
		return false
	}

	allowedStr := strings.TrimSpace(os.Getenv("ALLOWED_ORIGINS"))
	var allowedList []string
	if allowedStr != "" {
		allowedList = strings.Split(allowedStr, ",")
	} else {
		allowedList = []string{
			"http://localhost:3000",
			"http://127.0.0.1:3000",
			"http://localhost:8000",
			"http://127.0.0.1:8000",
			"https://localhost:3000",
			"https://127.0.0.1:3000",
		}
	}

	normOrigin := strings.ToLower(strings.TrimRight(origin, "/"))
	for _, item := range allowedList {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if item == "*" {
			if os.Getenv("ENV") == "production" || os.Getenv("NODE_ENV") == "production" {
				log.Println("⚠️ [WS ORIGIN] Ký tự đại diện '*' bị cấm trong production")
				continue
			}
			return true
		}
		if strings.ToLower(strings.TrimRight(item, "/")) == normOrigin {
			return true
		}
	}

	// Cho phép kết nối nếu cùng Host với backend hoặc reverse proxy
	if strings.EqualFold(parsedOrigin.Host, r.Host) {
		return true
	}

	log.Printf("⛔ [WS REJECT] Origin '%s' không nằm trong allowlist", origin)
	return false
}

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin:     checkWebSocketOrigin,
}

// ChatClient đại diện cho 1 kết nối WebSocket của 1 người xem
type ChatClient struct {
	hub           *ChatHub
	conn          *websocket.Conn
	send          chan []byte
	streamKey     string
	username      string
	role          string
	authenticated bool
	rateLimiter   *TokenBucket
}

// ChatHub quản lý các phòng chat theo từng streamKey
type ChatHub struct {
	rooms      map[string]map[*ChatClient]bool // streamKey -> set of clients
	broadcast  chan broadcastEvent
	register   chan *ChatClient
	unregister chan *ChatClient
	mutex      sync.RWMutex
}

type broadcastEvent struct {
	streamKey string
	message   []byte
}

var globalChatHub = &ChatHub{
	rooms:      make(map[string]map[*ChatClient]bool),
	broadcast:  make(chan broadcastEvent, 256),
	register:   make(chan *ChatClient),
	unregister: make(chan *ChatClient),
}

func init() {
	go globalChatHub.run()
}

// run vòng lặp xử lý các sự kiện của ChatHub
func (h *ChatHub) run() {
	for {
		select {
		case client := <-h.register:
			h.mutex.Lock()
			if _, ok := h.rooms[client.streamKey]; !ok {
				h.rooms[client.streamKey] = make(map[*ChatClient]bool)
			}
			h.rooms[client.streamKey][client] = true
			count := len(h.rooms[client.streamKey])
			h.mutex.Unlock()

			log.Printf("[CHAT CONNECT] User '%s' (%s) vào phòng '%s'. Tổng người xem: %d", client.username, client.role, client.streamKey, count)
			h.broadcastViewerCount(client.streamKey, count)

		case client := <-h.unregister:
			h.mutex.Lock()
			if clients, ok := h.rooms[client.streamKey]; ok {
				if _, exists := clients[client]; exists {
					delete(clients, client)
					close(client.send)
					count := len(clients)
					if count == 0 {
						delete(h.rooms, client.streamKey)
					}
					h.mutex.Unlock()

					log.Printf("[CHAT DISCONNECT] User '%s' rời phòng '%s'. Còn lại: %d", client.username, client.streamKey, count)
					h.broadcastViewerCount(client.streamKey, count)
					continue
				}
			}
			h.mutex.Unlock()

		case event := <-h.broadcast:
			h.mutex.RLock()
			if clients, ok := h.rooms[event.streamKey]; ok {
				for client := range clients {
					select {
					case client.send <- event.message:
					default:
						// Buffer đầy -> đóng kết nối
						close(client.send)
						delete(clients, client)
					}
				}
			}
			h.mutex.RUnlock()
		}
	}
}

// broadcastViewerCount gửi số lượng người xem hiện tại cho phòng
func (h *ChatHub) broadcastViewerCount(streamKey string, count int) {
	out := WSOutboundMessage{
		Type:        "viewer_count",
		ViewerCount: count,
	}
	bytes, err := json.Marshal(out)
	if err == nil {
		h.broadcast <- broadcastEvent{streamKey: streamKey, message: bytes}
	}
}

// readPump lắng nghe các tin nhắn gửi từ client lên
func (c *ChatClient) readPump() {
	defer func() {
		c.hub.unregister <- c
		c.conn.Close()
	}()

	c.conn.SetReadLimit(4096)
	c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	c.conn.SetPongHandler(func(string) error {
		c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	for {
		_, messageBytes, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("Lỗi kết nối websocket: %v", err)
			}
			break
		}

		var in WSInboundMessage
		if err := json.Unmarshal(messageBytes, &in); err != nil {
			continue
		}

		// Rate limiting trên từng kết nối WebSocket (chống spam message)
		if c.rateLimiter != nil && !c.rateLimiter.Allow() {
			warn := WSOutboundMessage{
				Type:  "error",
				Error: "Bạn đang gửi tin nhắn quá nhanh. Vui lòng chậm lại.",
			}
			if b, err := json.Marshal(warn); err == nil {
				c.send <- b
			}
			continue
		}

		// RÀNG BUỘC P1-4: Không xử lý message nghiệp vụ (chat, reaction) trước khi xác thực thành công
		if !c.authenticated && in.Type != "auth_token" && in.Type != "auth_guest" && in.Type != "auth_login" {
			warn := WSOutboundMessage{
				Type:  "error",
				Error: "Yêu cầu hoàn tất xác thực WebSocket (auth_token hoặc auth_guest) trước khi thao tác",
			}
			if b, err := json.Marshal(warn); err == nil {
				c.send <- b
			}
			continue
		}

		switch in.Type {
		case "auth_login":
			// Xác thực đăng nhập qua WebSocket (tương thích Mobile Studio)
			var resp WSOutboundMessage
			resp.Type = "auth_login_result"

			uName := strings.ToLower(strings.TrimSpace(in.Username))
			pwd := strings.TrimSpace(in.Password)

			if usersColl == nil {
				resp.Error = "Cơ sở dữ liệu chưa sẵn sàng, vui lòng thử lại sau giây lát!"
				if b, err := json.Marshal(resp); err == nil {
					c.send <- b
				}
				continue
			}

			var user User
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			errU := usersColl.FindOne(ctx, bson.M{"username": uName}).Decode(&user)
			cancel()

			if errU != nil || bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(pwd)) != nil {
				resp.Error = "Tên đăng nhập hoặc mật khẩu không chính xác!"
				if b, err := json.Marshal(resp); err == nil {
					c.send <- b
				}
				continue
			}

			if user.Role == "systemadmin" {
				resp.Error = "⛔ Tài khoản SystemAdmin (Tổng Quản Trị) không có quyền phát sóng! Vui lòng dùng tài khoản Admin."
				if b, err := json.Marshal(resp); err == nil {
					c.send <- b
				}
				continue
			}

			if user.Role != "admin" {
				resp.Error = "⛔ Tài khoản này là Người xem (User). Chỉ có tài khoản vai trò Admin mới được livestream!"
				if b, err := json.Marshal(resp); err == nil {
					c.send <- b
				}
				continue
			}

			// Tạo JWT token
			token, _ := createToken(user)

			// Lấy các stream keys của admin này
			var userKeys []StreamKey
			ctxK, cancelK := context.WithTimeout(context.Background(), 5*time.Second)
			cursor, _ := keysColl.Find(ctxK, bson.M{
				"$and": []bson.M{
					{"is_active": true},
					{
						"$or": []bson.M{
							{"user_id": user.ID},
							{"streamer": user.FullName},
							{"streamer": user.Username},
						},
					},
				},
			})
			if cursor != nil {
				_ = cursor.All(ctxK, &userKeys)
				_ = cursor.Close(ctxK)
			}
			cancelK()

			primaryKey := user.Username
			if len(userKeys) > 0 {
				primaryKey = userKeys[0].Key
			}

			resp.Success = true
			resp.Token = token
			resp.User = &user
			resp.StreamKey = primaryKey
			resp.StreamKeys = userKeys

			c.username = user.FullName
			if c.username == "" {
				c.username = user.Username
			}
			c.role = user.Role
			c.authenticated = true

			recordAccessLog(user.Username, user.Role, "login", c.conn.RemoteAddr().String(), "Đăng nhập thành công từ Mobile Studio")

			if b, err := json.Marshal(resp); err == nil {
				c.send <- b
			}

			c.sendChatHistory()

		case "auth_token":
			tStr := strings.TrimSpace(in.Token)
			tStr = strings.TrimPrefix(tStr, "Bearer ")
			tStr = strings.TrimPrefix(tStr, "bearer ")

			if tStr == "" || len(tStr) > 4096 {
				c.sendAuthErrorAndClose("Token xác thực rỗng hoặc kích thước vượt giới hạn")
				return
			}

			// Kiểm tra thu hồi token (P1-5)
			if globalTokenRevocationStore.IsTokenRevoked(tStr) {
				c.sendAuthErrorAndClose("Token đã bị thu hồi do đăng xuất")
				return
			}

			token, err := jwt.ParseWithClaims(tStr, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
				return jwtSecret, nil
			})
			if err != nil || !token.Valid {
				c.sendAuthErrorAndClose("Token không hợp lệ hoặc đã hết hạn")
				return
			}

			claims, ok := token.Claims.(*JWTClaims)
			if !ok {
				c.sendAuthErrorAndClose("Claims token không hợp lệ")
				return
			}

			displayName := claims.Username
			if claims.Role == "systemadmin" || claims.Username == "sysadmin" {
				displayName = "Ban Quản Trị"
			} else if claims.Role == "admin" || claims.Username == "admin01" {
				displayName = "Chủ Trại"
			}

			c.username = displayName
			c.role = claims.Role
			c.authenticated = true

			ack := WSOutboundMessage{
				Type:    "auth_login_result",
				Success: true,
				User:    &User{Username: displayName, Role: claims.Role},
			}
			if b, err := json.Marshal(ack); err == nil {
				c.send <- b
			}

			c.sendChatHistory()

		case "auth_guest":
			gName := strings.TrimSpace(in.GuestName)
			if gName == "" {
				gName = strings.TrimSpace(in.Sender)
			}
			if gName == "" {
				gName = fmt.Sprintf("Khách_%d", time.Now().Unix()%10000)
			}
			if len(gName) > 30 {
				gName = gName[:30]
			}
			gName = strings.ReplaceAll(gName, "\n", "")
			gName = strings.ReplaceAll(gName, "\r", "")

			c.username = gName
			c.role = "guest"
			c.authenticated = true

			ack := WSOutboundMessage{
				Type:    "auth_login_result",
				Success: true,
				User:    &User{Username: gName, Role: "guest"},
			}
			if b, err := json.Marshal(ack); err == nil {
				c.send <- b
			}

			c.sendChatHistory()

		case "reaction":
			// Thả tim/biểu cảm nhanh
			emoji := strings.TrimSpace(in.Emoji)
			if emoji == "" {
				emoji = "❤️"
			}
			out := WSOutboundMessage{
				Type:   "reaction",
				Emoji:  emoji,
				Sender: c.username,
			}
			if b, err := json.Marshal(out); err == nil {
				c.hub.broadcast <- broadcastEvent{streamKey: c.streamKey, message: b}
			}

		case "chat":
			msgText := strings.TrimSpace(in.Message)
			if msgText == "" {
				continue
			}
			if len(msgText) > 400 {
				msgText = msgText[:400]
			}

			chatMsg := ChatMessage{
				ID:        primitive.NewObjectID(),
				StreamKey: c.streamKey,
				Username:  c.username,
				Role:      c.role,
				Message:   msgText,
				Type:      "chat",
				CreatedAt: time.Now(),
			}

			// Lưu tin nhắn vào MongoDB Atlas
			go saveChatMessage(chatMsg)

			out := WSOutboundMessage{
				Type: "chat",
				Data: &chatMsg,
			}
			if b, err := json.Marshal(out); err == nil {
				c.hub.broadcast <- broadcastEvent{streamKey: c.streamKey, message: b}
			}
		}
	}
}

// sendChatHistory gửi danh sách tin nhắn gần đây cho socket sau khi xác thực
func (c *ChatClient) sendChatHistory() {
	history := getRecentChatHistory(c.streamKey)
	historyMsg := WSOutboundMessage{
		Type:    "history",
		History: history,
	}
	if hBytes, err := json.Marshal(historyMsg); err == nil {
		c.send <- hBytes
	}
}

// sendAuthErrorAndClose gửi thông báo lỗi xác thực và đóng socket an toàn
func (c *ChatClient) sendAuthErrorAndClose(reason string) {
	resp := WSOutboundMessage{
		Type:    "auth_login_result",
		Success: false,
		Error:   reason,
	}
	if b, err := json.Marshal(resp); err == nil {
		c.send <- b
	}
	_ = c.conn.WriteControl(
		websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.ClosePolicyViolation, reason),
		time.Now().Add(time.Second),
	)
	c.conn.Close()
}

// writePump gửi các tin nhắn từ hub ra client và duy trì heartbeat ping
func (c *ChatClient) writePump() {
	ticker := time.NewTicker(25 * time.Second)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()

	for {
		select {
		case message, ok := <-c.send:
			c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if !ok {
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			if err := c.conn.WriteMessage(websocket.TextMessage, message); err != nil {
				return
			}

		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// saveChatMessage lưu tin nhắn vào MongoDB collection chat_messages
func saveChatMessage(msg ChatMessage) {
	if chatColl == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := chatColl.InsertOne(ctx, msg)
	if err != nil {
		log.Printf("⚠️ Không thể lưu tin nhắn chat vào MongoDB: %v", err)
	}
}

// getRecentChatHistory lấy 50 tin nhắn mới nhất của phòng
func getRecentChatHistory(streamKey string) []ChatMessage {
	if chatColl == nil {
		return []ChatMessage{}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	opts := options.Find().SetSort(bson.M{"created_at": -1}).SetLimit(50)
	cursor, err := chatColl.Find(ctx, bson.M{"stream_key": streamKey}, opts)
	if err != nil {
		return []ChatMessage{}
	}
	defer cursor.Close(ctx)

	msgs := make([]ChatMessage, 0)
	_ = cursor.All(ctx, &msgs)

	// Đảo ngược lại thứ tự để tin nhắn cũ ở trên, mới ở dưới và ẩn username nhạy cảm
	for i, j := 0, len(msgs)-1; i < j; i, j = i+1, j-1 {
		msgs[i], msgs[j] = msgs[j], msgs[i]
	}
	for i := range msgs {
		if msgs[i].Username == "sysadmin" || msgs[i].Role == "systemadmin" {
			msgs[i].Username = "Ban Quản Trị"
		} else if msgs[i].Username == "admin01" {
			msgs[i].Username = "Chủ Trại"
		}
	}

	return msgs
}

// wsChatHandler xử lý nâng cấp WebSocket cho phòng chat
// GET /ws/chat?streamKey=tiendev
func wsChatHandler(w http.ResponseWriter, r *http.Request) {
	streamKey := strings.TrimSpace(r.URL.Query().Get("streamKey"))
	if streamKey == "" {
		http.Error(w, "streamKey is required", http.StatusBadRequest)
		return
	}

	// Nâng cấp kết nối HTTP lên WebSocket (sử dụng Origin allowlist)
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("❌ Lỗi nâng cấp WebSocket: %v", err)
		return
	}

	client := &ChatClient{
		hub:           globalChatHub,
		conn:          conn,
		send:          make(chan []byte, 128),
		streamKey:     streamKey,
		username:      "",
		role:          "guest",
		authenticated: false,
		rateLimiter:   NewTokenBucket(5.0, 10.0), // 5 msg/sec, burst 10
	}

	client.hub.register <- client

	// Timeout xác thực: đóng kết nối an toàn nếu sau 10 giây client chưa gửi message xác thực
	go func() {
		time.Sleep(10 * time.Second)
		if !client.authenticated {
			client.sendAuthErrorAndClose("Quá thời gian xác thực WebSocket")
		}
	}()

	// Chạy song song reader và writer
	go client.writePump()
	go client.readPump()
}

// apiChatHistoryHandler REST API lấy lịch sử chat
// GET /api/chat/history?streamKey=tiendev
func apiChatHistoryHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	streamKey := strings.TrimSpace(r.URL.Query().Get("streamKey"))
	if streamKey == "" {
		http.Error(w, `{"error":"streamKey is required"}`, http.StatusBadRequest)
		return
	}

	history := getRecentChatHistory(streamKey)
	json.NewEncoder(w).Encode(history)
}
