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
	SessionID string             `bson:"session_id,omitempty" json:"session_id,omitempty"` // ID phiên live (để lưu trữ và xem lại)
	StreamKey string             `bson:"stream_key" json:"stream_key"`
	Username  string             `bson:"username" json:"username"`
	Avatar    string             `bson:"avatar,omitempty" json:"avatar,omitempty"`
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

// isOriginAllowed kiểm tra xem Origin có nằm trong danh sách ALLOWED_ORIGINS hợp lệ hay không (dùng chung cho cả REST CORS và WebSocket)
func isOriginAllowed(origin string, requestHost string) bool {
	origin = strings.TrimSpace(origin)
	if origin == "" {
		return false
	}

	parsedOrigin, err := url.Parse(origin)
	if err != nil || parsedOrigin.Host == "" {
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
			"http://localhost:5173",
			"http://127.0.0.1:5173",
			"http://localhost:8000",
			"http://127.0.0.1:8000",
			"https://localhost:3000",
			"https://127.0.0.1:3000",
			"https://traiga-fe.vercel.app",
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
				log.Println("⚠️ [ORIGIN] Ký tự đại diện '*' bị cấm trong production")
				continue
			}
			return true
		}
		if strings.ToLower(strings.TrimRight(item, "/")) == normOrigin {
			return true
		}
	}

	// Cho phép kết nối nếu cùng Host với backend hoặc reverse proxy
	if requestHost != "" && strings.EqualFold(parsedOrigin.Host, requestHost) {
		return true
	}

	return false
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

	if !isOriginAllowed(origin, r.Host) {
		log.Printf("⛔ [WS REJECT] Origin '%s' không nằm trong allowlist", origin)
		return false
	}
	return true
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
	avatar        string
	role          string
	clientIP      string
	authenticated bool
	rateLimiter   *TokenBucket
}

// getIP trả về địa chỉ IP thực của client WebSocket
func (c *ChatClient) getIP() string {
	if c.clientIP != "" {
		return c.clientIP
	}
	if c.conn != nil && c.conn.RemoteAddr() != nil {
		return c.conn.RemoteAddr().String()
	}
	return "unknown"
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

			// Áp dụng Rate Limit chống dò mật khẩu qua WebSocket
			initRateLimiters()
			if loginLimiter != nil && !loginLimiter.Allow(c.getIP()) {
				resp.Error = "Quá nhiều lần thử đăng nhập từ địa chỉ này. Vui lòng thử lại sau 1 phút."
				if b, err := json.Marshal(resp); err == nil {
					c.send <- b
				}
				continue
			}

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

			// Tạo JWT token và đồng bộ thu hồi phiên cũ (Single-Device Session)
			token, _ := createToken(user)
			globalTokenRevocationStore.SetActiveUserToken(user.Username, token, time.Now().Add(7*24*time.Hour))

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
			c.avatar = user.Avatar
			c.role = user.Role
			c.authenticated = true

			recordAccessLog(user.Username, user.Role, "login", c.getIP(), "Đăng nhập thành công từ Mobile Studio")

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
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
				}
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

			userAvatar := ""
			if usersColl != nil {
				if objID, errID := primitive.ObjectIDFromHex(claims.UserID); errID == nil {
					ctxU, cancelU := context.WithTimeout(context.Background(), 2*time.Second)
					var u User
					if errU := usersColl.FindOne(ctxU, bson.M{"_id": objID}).Decode(&u); errU == nil {
						userAvatar = u.Avatar
						if u.FullName != "" && claims.Role != "systemadmin" {
							displayName = u.FullName
						}
					}
					cancelU()
				}
			}

			c.username = displayName
			c.avatar = userAvatar
			c.role = claims.Role
			c.authenticated = true

			ack := WSOutboundMessage{
				Type:    "auth_login_result",
				Success: true,
				User:    &User{Username: displayName, Role: claims.Role, Avatar: userAvatar},
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
				Avatar:    c.avatar,
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

// saveChatMessage lưu tin nhắn vào MongoDB collection chat_messages (luôn lưu trữ vĩnh viễn trong DB)
func saveChatMessage(msg ChatMessage) {
	if chatColl == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Tự động gắn SessionID nếu đang trong phiên live để tiện tra cứu / xem lại theo từng phiên
	if msg.SessionID == "" && sessionsColl != nil && msg.StreamKey != "" {
		var activeSess LiveSession
		optsSess := options.FindOne().SetSort(bson.M{"started_at": -1})
		if err := sessionsColl.FindOne(ctx, bson.M{"stream_key": msg.StreamKey, "status": "live"}, optsSess).Decode(&activeSess); err == nil {
			msg.SessionID = activeSess.ID.Hex()
		}
	}

	_, err := chatColl.InsertOne(ctx, msg)
	if err != nil {
		log.Printf("⚠️ Không thể lưu tin nhắn chat vào MongoDB: %v", err)
	}
}

// broadcastResetChat gửi sự kiện reset/xóa trắng khung chat tới tất cả người xem trong phòng
func broadcastResetChat(streamKey string) {
	out := WSOutboundMessage{
		Type: "reset_chat",
	}
	if b, err := json.Marshal(out); err == nil {
		globalChatHub.broadcast <- broadcastEvent{streamKey: streamKey, message: b}
	}
}

// resetRoomChat phát lệnh reset khung chat trên giao diện người xem, giữ nguyên 100% dữ liệu tin nhắn lưu trong DB
func resetRoomChat(streamKey string) {
	if streamKey == "" {
		return
	}
	// Tuyệt đối không xóa tin nhắn trong MongoDB (chat_messages) để phục vụ lưu trữ vĩnh viễn và xem lại.
	// Chỉ phát tín hiệu reset cho client đang kết nối bắt đầu phiên trò chuyện mới.
	broadcastResetChat(streamKey)
}

// clearRoomChatHistory giữ tên hàm tương thích với các điểm gọi cũ, chỉ reset giao diện chứ không xóa DB
func clearRoomChatHistory(streamKey string) {
	resetRoomChat(streamKey)
}

// getRecentChatHistory lấy các tin nhắn của phiên live hiện tại (nếu offline thì không hiển thị lịch sử cũ)
func getRecentChatHistory(streamKey string) []ChatMessage {
	if chatColl == nil {
		return []ChatMessage{}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Nếu có sessionsColl, kiểm tra xem phòng có phiên live đang hoạt động hay không
	if sessionsColl != nil {
		var activeSession LiveSession
		optsSess := options.FindOne().SetSort(bson.M{"started_at": -1})
		err := sessionsColl.FindOne(ctx, bson.M{"stream_key": streamKey, "status": "live"}, optsSess).Decode(&activeSession)
		if err != nil {
			// Luồng không live (offline) -> Trả về mảng rỗng, không hiện lịch sử quá khứ
			return []ChatMessage{}
		}

		// Chỉ lấy các tin nhắn phát sinh trong phiên live hiện tại (từ started_at trở đi)
		opts := options.Find().SetSort(bson.M{"created_at": -1}).SetLimit(50)
		filter := bson.M{
			"stream_key": streamKey,
			"created_at": bson.M{"$gte": activeSession.StartedAt},
		}
		cursor, err := chatColl.Find(ctx, filter, opts)
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

	return []ChatMessage{}
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
		clientIP:      getClientIP(r),
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
// GET /api/chat/history?streamKey=tiendev&sessionId=... (hỗ trợ xem lại tin nhắn của các phiên live cũ trong DB)
func apiChatHistoryHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	streamKey := strings.TrimSpace(r.URL.Query().Get("streamKey"))
	if streamKey == "" {
		http.Error(w, `{"error":"streamKey is required"}`, http.StatusBadRequest)
		return
	}

	sessionID := strings.TrimSpace(r.URL.Query().Get("sessionId"))
	if sessionID != "" && chatColl != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		opts := options.Find().SetSort(bson.M{"created_at": 1}).SetLimit(500)
		filter := bson.M{"stream_key": streamKey, "session_id": sessionID}
		cursor, err := chatColl.Find(ctx, filter, opts)
		if err == nil {
			defer cursor.Close(ctx)
			msgs := make([]ChatMessage, 0)
			_ = cursor.All(ctx, &msgs)
			for i := range msgs {
				if msgs[i].Username == "sysadmin" || msgs[i].Role == "systemadmin" {
					msgs[i].Username = "Ban Quản Trị"
				} else if msgs[i].Username == "admin01" {
					msgs[i].Username = "Chủ Trại"
				}
			}
			json.NewEncoder(w).Encode(msgs)
			return
		}
	}

	history := getRecentChatHistory(streamKey)
	json.NewEncoder(w).Encode(history)
}
