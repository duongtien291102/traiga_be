package chat

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"golang.org/x/crypto/bcrypt"

	"livestream-be/internal/model"
	"livestream-be/internal/security/limiter"
	"livestream-be/internal/security/token"
)

// BroadcastEvent đại diện cho một thông điệp được phát tán trong phòng live.
type BroadcastEvent struct {
	StreamKey    string
	Message      []byte
	OwnerMessage []byte
}

// Client đại diện cho 1 kết nối WebSocket của 1 người xem.
type Client struct {
	Hub           *Hub
	Conn          *websocket.Conn
	Send          chan []byte
	StreamKey     string
	Username      string
	Avatar        string
	Role          string
	UserID        string
	RoomOwner     bool
	ClientIP      string
	Authenticated bool
	RateLimiter   *limiter.TokenBucket
	mu            sync.RWMutex
	closed        bool
}

// SafeSend gửi dữ liệu an toàn vào channel Send, chống panic send on closed channel
func (c *Client) SafeSend(msg []byte) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return false
	}
	defer func() {
		_ = recover()
	}()
	select {
	case c.Send <- msg:
		return true
	default:
		return false
	}
}

// CloseSend đóng channel Send an toàn đúng 1 lần
func (c *Client) CloseSend() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.closed {
		c.closed = true
		defer func() {
			_ = recover()
		}()
		close(c.Send)
	}
}

// IsClosed kiểm tra xem client đã đóng kết nối chưa
func (c *Client) IsClosed() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.closed
}

// GetIP trả về địa chỉ IP thực của client WebSocket.
func (c *Client) GetIP() string {
	if c.ClientIP != "" {
		return c.ClientIP
	}
	if c.Conn != nil && c.Conn.RemoteAddr() != nil {
		return c.Conn.RemoteAddr().String()
	}
	return "unknown"
}

// Hub quản lý các phòng chat theo từng streamKey.
type Hub struct {
	Rooms      map[string]map[*Client]bool // streamKey -> set of clients
	Broadcast  chan BroadcastEvent
	Register   chan *Client
	Unregister chan *Client
	Mutex      sync.RWMutex
}

// NewHub khởi tạo Hub quản lý WebSocket.
func NewHub() *Hub {
	return &Hub{
		Rooms:      make(map[string]map[*Client]bool),
		Broadcast:  make(chan BroadcastEvent, 256),
		Register:   make(chan *Client),
		Unregister: make(chan *Client),
	}
}

// Run chạy vòng lặp xử lý sự kiện đăng ký, hủy và broadcast của Hub.
func (h *Hub) Run() {
	for {
		select {
		case client := <-h.Register:
			h.Mutex.Lock()
			if _, ok := h.Rooms[client.StreamKey]; !ok {
				h.Rooms[client.StreamKey] = make(map[*Client]bool)
			}
			h.Rooms[client.StreamKey][client] = true
			count := len(h.Rooms[client.StreamKey])
			h.Mutex.Unlock()

			log.Printf("[CHAT CONNECT] User '%s' (%s) vào phòng '%s'. Tổng người xem: %d", client.Username, client.Role, client.StreamKey, count)
			h.BroadcastViewerCount(client.StreamKey, count)

		case client := <-h.Unregister:
			h.Mutex.Lock()
			if clients, ok := h.Rooms[client.StreamKey]; ok {
				if _, exists := clients[client]; exists {
					delete(clients, client)
					client.CloseSend()
					count := len(clients)
					if count == 0 {
						delete(h.Rooms, client.StreamKey)
					}
					h.Mutex.Unlock()

					log.Printf("[CHAT DISCONNECT] User '%s' rời phòng '%s'. Còn lại: %d", client.Username, client.StreamKey, count)
					h.BroadcastViewerCount(client.StreamKey, count)
					continue
				}
			}
			h.Mutex.Unlock()

		case event := <-h.Broadcast:
			h.Mutex.RLock()
			if clients, ok := h.Rooms[event.StreamKey]; ok {
				for client := range clients {
					message := event.Message
					if client.RoomOwner && len(event.OwnerMessage) > 0 {
						message = event.OwnerMessage
					}
					if !client.SafeSend(message) {
						client.CloseSend()
						delete(clients, client)
					}
				}
			}
			h.Mutex.RUnlock()
		}
	}
}

// BroadcastViewerCount gửi số lượng người xem hiện tại cho phòng.
func (h *Hub) BroadcastViewerCount(streamKey string, count int) {
	out := model.WSOutboundMessage{
		Type:        "viewer_count",
		ViewerCount: count,
	}
	bytes, err := json.Marshal(out)
	if err == nil {
		h.Broadcast <- BroadcastEvent{StreamKey: streamKey, Message: bytes}
	}
}

// BroadcastResetChat gửi sự kiện reset/xóa trắng khung chat tới tất cả người xem trong phòng.
func (h *Hub) BroadcastResetChat(streamKey string) {
	out := model.WSOutboundMessage{
		Type: "reset_chat",
	}
	if b, err := json.Marshal(out); err == nil {
		h.Broadcast <- BroadcastEvent{StreamKey: streamKey, Message: b}
	}
}

// ViewerCount trả về số lượng client đang kết nối trong phòng streamKey.
func (h *Hub) ViewerCount(streamKey string) int {
	if h == nil {
		return 0
	}
	h.Mutex.RLock()
	defer h.Mutex.RUnlock()
	if clients, ok := h.Rooms[streamKey]; ok {
		return len(clients)
	}
	return 0
}

// BroadcastMessage gửi thông điệp tới phòng streamKey với bản tin riêng cho owner nếu có.
func (h *Hub) BroadcastMessage(streamKey string, publicMessage, ownerMessage []byte) {
	if h != nil && h.Broadcast != nil {
		h.Broadcast <- BroadcastEvent{
			StreamKey:    streamKey,
			Message:      publicMessage,
			OwnerMessage: ownerMessage,
		}
	}
}

// ReadPump lắng nghe các tin nhắn từ kết nối client lên.
func (c *Client) ReadPump(svc *Service) {
	defer func() {
		c.Hub.Unregister <- c
		c.Conn.Close()
	}()

	c.Conn.SetReadLimit(4096)
	c.Conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	c.Conn.SetPongHandler(func(string) error {
		c.Conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	for {
		_, messageBytes, err := c.Conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("Lỗi kết nối websocket: %v", err)
			}
			break
		}

		var in model.WSInboundMessage
		if err := json.Unmarshal(messageBytes, &in); err != nil {
			continue
		}

		if c.RateLimiter != nil && !c.RateLimiter.Allow() {
			warn := model.WSOutboundMessage{
				Type:  "error",
				Error: "Bạn đang gửi tin nhắn quá nhanh. Vui lòng chậm lại.",
			}
			if b, err := json.Marshal(warn); err == nil {
				c.SafeSend(b)
			}
			continue
		}

		if !c.Authenticated && in.Type != "auth_token" && in.Type != "auth_guest" && in.Type != "auth_login" {
			warn := model.WSOutboundMessage{
				Type:  "error",
				Error: "Yêu cầu hoàn tất xác thực WebSocket (auth_token hoặc auth_guest) trước khi thao tác",
			}
			if b, err := json.Marshal(warn); err == nil {
				c.SafeSend(b)
			}
			continue
		}

		switch in.Type {
		case "auth_login":
			var resp model.WSOutboundMessage
			resp.Type = "auth_login_result"

			limiter.InitRateLimiters()
			if limiter.LoginLimiter != nil && !limiter.LoginLimiter.Allow(c.GetIP()) {
				resp.Error = "Quá nhiều lần thử đăng nhập từ địa chỉ này. Vui lòng thử lại sau 1 phút."
				if b, err := json.Marshal(resp); err == nil {
					c.SafeSend(b)
				}
				continue
			}

			uName := strings.ToLower(strings.TrimSpace(in.Username))
			pwd := strings.TrimSpace(in.Password)

			var st = svc.GetStore()
			if st == nil || st.Users == nil {
				resp.Error = "Cơ sở dữ liệu chưa sẵn sàng, vui lòng thử lại sau giây lát!"
				if b, err := json.Marshal(resp); err == nil {
					c.SafeSend(b)
				}
				continue
			}

			var user model.User
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			errU := st.Users.FindOne(ctx, bson.M{"username": uName}).Decode(&user)
			cancel()

			if errU != nil || bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(pwd)) != nil {
				resp.Error = "Tên đăng nhập hoặc mật khẩu không chính xác!"
				if b, err := json.Marshal(resp); err == nil {
					c.SafeSend(b)
				}
				continue
			}

			if user.Role == "systemadmin" {
				resp.Error = "⛔ Tài khoản SystemAdmin (Tổng Quản Trị) không có quyền phát sóng! Vui lòng dùng tài khoản Admin."
				if b, err := json.Marshal(resp); err == nil {
					c.SafeSend(b)
				}
				continue
			}

			if user.Role != "admin" {
				resp.Error = "⛔ Tài khoản này là Người xem (User). Chỉ có tài khoản vai trò Admin mới được livestream!"
				if b, err := json.Marshal(resp); err == nil {
					c.SafeSend(b)
				}
				continue
			}

			tok, _ := svc.CreateToken(user)
			token.Global().SetActiveUserToken(user.Username, tok, time.Now().Add(7*24*time.Hour))

			var userKeys []model.StreamKey
			ctxK, cancelK := context.WithTimeout(context.Background(), 5*time.Second)
			if st.Keys != nil {
				cursor, _ := st.Keys.Find(ctxK, bson.M{
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
			}
			cancelK()

			for i := range userKeys {
				if svc.HydratePublishSecret != nil {
					if err := svc.HydratePublishSecret(&userKeys[i]); err != nil {
						log.Printf("[AUTH WS] Không thể mở khóa phát cho phòng %s: %v", userKeys[i].ID.Hex(), err)
						userKeys[i].PublishSecret = ""
					}
				}
			}

			primaryKey := user.Username
			primaryPublishSecret := ""
			if len(userKeys) > 0 {
				primaryKey = userKeys[0].Key
				primaryPublishSecret = userKeys[0].PublishSecret
			}

			credentials := make([]model.StreamKeyCredential, 0, len(userKeys))
			for _, k := range userKeys {
				credentials = append(credentials, model.StreamKeyCredential{StreamKey: k, PublishSecret: k.PublishSecret})
			}

			resp.Success = true
			resp.Token = tok
			resp.User = &user
			resp.StreamKey = primaryKey
			resp.PublishSecret = primaryPublishSecret
			resp.StreamKeys = credentials

			c.Username = user.FullName
			if c.Username == "" {
				c.Username = user.Username
			}
			c.Avatar = user.Avatar
			c.Role = user.Role
			c.UserID = user.ID.Hex()
			c.RoomOwner = svc.IsRoomOwnerUserID(c.StreamKey, c.UserID)
			c.Authenticated = true

			if svc.RecordAccessLog != nil {
				svc.RecordAccessLog(user.Username, user.Role, "login", c.GetIP(), "Đăng nhập thành công từ Mobile Studio")
			}

			if b, err := json.Marshal(resp); err == nil {
				c.SafeSend(b)
			}

			c.SendChatHistory(svc)

		case "auth_token":
			tStr := strings.TrimSpace(in.Token)
			tStr = strings.TrimPrefix(tStr, "Bearer ")
			tStr = strings.TrimPrefix(tStr, "bearer ")

			if tStr == "" || len(tStr) > 4096 {
				c.FallbackToGuest(in.Sender, "Token xác thực rỗng", svc)
				continue
			}

			if token.Global().IsTokenRevoked(tStr) {
				c.FallbackToGuest(in.Sender, "Token đã bị thu hồi do đăng xuất", svc)
				continue
			}

			var secret []byte
			if svc.GetJwtSecret != nil {
				secret = svc.GetJwtSecret()
			}

			tok, err := jwt.ParseWithClaims(tStr, &model.JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
				}
				return secret, nil
			})
			if err != nil || !tok.Valid {
				c.FallbackToGuest(in.Sender, "Token không hợp lệ hoặc đã hết hạn", svc)
				continue
			}

			claims, ok := tok.Claims.(*model.JWTClaims)
			if !ok {
				c.FallbackToGuest(in.Sender, "Claims token không hợp lệ", svc)
				continue
			}

			displayName := claims.Username
			if claims.Role == "systemadmin" || claims.Username == "sysadmin" {
				displayName = "Ban Quản Trị"
			} else if claims.Role == "admin" || claims.Username == "admin01" {
				displayName = "Chủ Trại"
			}

			userAvatar := ""
			st := svc.GetStore()
			if st != nil && st.Users != nil {
				if objID, errID := primitive.ObjectIDFromHex(claims.UserID); errID == nil {
					ctxU, cancelU := context.WithTimeout(context.Background(), 2*time.Second)
					var u model.User
					if errU := st.Users.FindOne(ctxU, bson.M{"_id": objID}).Decode(&u); errU == nil {
						userAvatar = u.Avatar
						if u.FullName != "" && claims.Role != "systemadmin" {
							displayName = u.FullName
						}
					}
					cancelU()
				}
			}

			c.Username = displayName
			c.Avatar = userAvatar
			c.Role = claims.Role
			c.UserID = claims.UserID
			c.RoomOwner = svc.IsRoomOwnerUserID(c.StreamKey, c.UserID)
			c.Authenticated = true

			ack := model.WSOutboundMessage{
				Type:    "auth_login_result",
				Success: true,
				User:    &model.User{Username: displayName, Role: claims.Role, Avatar: userAvatar},
			}
			if b, err := json.Marshal(ack); err == nil {
				c.SafeSend(b)
			}

			c.SendChatHistory(svc)

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

			c.Username = gName
			c.Role = "guest"
			c.Authenticated = true

			ack := model.WSOutboundMessage{
				Type:    "auth_login_result",
				Success: true,
				User:    &model.User{Username: gName, Role: "guest"},
			}
			if b, err := json.Marshal(ack); err == nil {
				c.SafeSend(b)
			}

			c.SendChatHistory(svc)

		case "reaction":
			emoji := strings.TrimSpace(in.Emoji)
			if emoji == "" {
				emoji = "❤️"
			}
			out := model.WSOutboundMessage{
				Type:   "reaction",
				Emoji:  emoji,
				Sender: c.Username,
			}
			if b, err := json.Marshal(out); err == nil {
				c.Hub.Broadcast <- BroadcastEvent{StreamKey: c.StreamKey, Message: b}
			}

		case "chat":
			msgText := strings.TrimSpace(in.Message)
			if msgText == "" {
				continue
			}
			if len(msgText) > 400 {
				msgText = msgText[:400]
			}

			chatMsg := model.ChatMessage{
				ID:        primitive.NewObjectID(),
				StreamKey: c.StreamKey,
				Username:  c.Username,
				Avatar:    c.Avatar,
				Role:      c.Role,
				Message:   msgText,
				Type:      "chat",
				CreatedAt: time.Now(),
			}

			go svc.SaveChatMessage(chatMsg)

			out := model.WSOutboundMessage{
				Type: "chat",
				Data: &chatMsg,
			}
			if b, err := json.Marshal(out); err == nil {
				maskedMsg := chatMsg
				maskedMsg.Message = MaskPhoneNumbers(maskedMsg.Message)
				maskedOut := model.WSOutboundMessage{Type: "chat", Data: &maskedMsg}
				maskedBytes, marshalErr := json.Marshal(maskedOut)
				if marshalErr == nil {
					c.Hub.Broadcast <- BroadcastEvent{StreamKey: c.StreamKey, Message: maskedBytes, OwnerMessage: b}
				}
			}
		}
	}
}

// SendChatHistory gửi danh sách tin nhắn gần đây cho socket sau khi xác thực.
func (c *Client) SendChatHistory(svc *Service) {
	history := svc.GetRecentChatHistory(c.StreamKey)
	if !c.RoomOwner {
		history = SanitizeChatHistory(history, false)
	}
	historyMsg := model.WSOutboundMessage{
		Type:    "history",
		History: history,
	}
	if hBytes, err := json.Marshal(historyMsg); err == nil {
		c.SafeSend(hBytes)
	}
}

// FallbackToGuest tự động chuyển sang chế độ Khách thay vì đóng socket khi token gặp sự cố.
func (c *Client) FallbackToGuest(sender string, reason string, svc *Service) {
	if c.IsClosed() {
		return
	}
	defer func() {
		_ = recover()
	}()

	gName := strings.TrimSpace(sender)
	if gName == "" {
		gName = fmt.Sprintf("Khách_%d", time.Now().Unix()%10000)
	}
	if len(gName) > 30 {
		gName = gName[:30]
	}
	c.Username = gName
	c.Role = "guest"
	c.Authenticated = true

	warn := model.WSOutboundMessage{
		Type:  "error",
		Error: reason + ", đã chuyển sang chế độ Khách",
	}
	if b, err := json.Marshal(warn); err == nil {
		c.SafeSend(b)
	}

	ack := model.WSOutboundMessage{
		Type:    "auth_login_result",
		Success: true,
		User:    &model.User{Username: gName, Role: "guest"},
	}
	if b, err := json.Marshal(ack); err == nil {
		c.SafeSend(b)
	}

	if !c.IsClosed() {
		c.SendChatHistory(svc)
	}
}

// WritePump gửi các tin nhắn từ hub ra client và duy trì heartbeat ping.
func (c *Client) WritePump() {
	ticker := time.NewTicker(25 * time.Second)
	defer func() {
		ticker.Stop()
		c.Conn.Close()
	}()

	for {
		select {
		case message, ok := <-c.Send:
			c.Conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if !ok {
				c.Conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			if err := c.Conn.WriteMessage(websocket.TextMessage, message); err != nil {
				return
			}

		case <-ticker.C:
			c.Conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := c.Conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}
