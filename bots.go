package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"strings"
	"sync"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// ChatBot đại diện cho 1 Bot tương tác được tạo bởi SystemAdmin
type ChatBot struct {
	ID        primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	Name      string             `bson:"name" json:"name"`             // Tên hiển thị của Bot
	Avatar    string             `bson:"avatar" json:"avatar"`         // Icon / Emoji đại diện
	Role      string             `bson:"role" json:"role"`             // "user" | "vip" | "streamer"
	Messages  []string           `bson:"messages" json:"messages"`     // Danh sách câu thoại đặt sẵn
	Interval  int                `bson:"interval" json:"interval"`     // Tần suất chat (giây, mặc định 15)
	IsActive  bool               `bson:"is_active" json:"is_active"`   // Cho phép sử dụng hay không
	CreatedBy string             `bson:"created_by" json:"created_by"` // Username SystemAdmin tạo
	CreatedAt time.Time          `bson:"created_at" json:"created_at"`
	UpdatedAt time.Time          `bson:"updated_at" json:"updated_at"`
}

// RoomBotAssignment lưu cấu hình bot mà Admin chọn cho phòng live của mình (tối đa 5 bot)
type RoomBotAssignment struct {
	ID        primitive.ObjectID   `bson:"_id,omitempty" json:"id"`
	StreamKey string               `bson:"stream_key" json:"stream_key"` // Khóa luồng live
	AdminUser string               `bson:"admin_user" json:"admin_user"` // Username của Admin
	BotIDs    []primitive.ObjectID `bson:"bot_ids" json:"bot_ids"`       // Danh sách tối đa 5 bot ID
	IsRunning bool                 `bson:"is_running" json:"is_running"` // Trạng thái đang chạy
	UpdatedAt time.Time            `bson:"updated_at" json:"updated_at"`
}

var (
	botsColl     *mongo.Collection
	roomBotsColl *mongo.Collection
)

// BotRunnerManager quản lý luồng chạy bot tự động theo từng phòng streamKey
type BotRunnerManager struct {
	runners map[string]chan struct{} // streamKey -> stop channel
	mutex   sync.Mutex
}

var globalBotManager = &BotRunnerManager{
	runners: make(map[string]chan struct{}),
}

// StartBots khởi động các bot đã chọn cho 1 phòng live
func (m *BotRunnerManager) StartBots(streamKey string, bots []ChatBot) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Nếu phòng này đang có bot chạy, dừng luồng cũ trước
	if stopCh, exists := m.runners[streamKey]; exists {
		close(stopCh)
		delete(m.runners, streamKey)
	}

	if len(bots) == 0 {
		return
	}

	// Đảm bảo tối đa 5 bot
	if len(bots) > 5 {
		bots = bots[:5]
	}

	stopCh := make(chan struct{})
	m.runners[streamKey] = stopCh

	log.Printf("🤖 [BOT RUNNER] Bắt đầu kích hoạt %d Bot vào phòng live '%s'", len(bots), streamKey)

	go func(key string, botList []ChatBot, ch chan struct{}) {
		// Tạo random generator cục bộ
		r := rand.New(rand.NewSource(time.Now().UnixNano()))

		// Vòng lặp phát tin nhắn tự động từ các bot
		for {
			// Chọn ngẫu nhiên 1 bot trong danh sách tối đa 5 bot
			botIndex := r.Intn(len(botList))
			bot := botList[botIndex]

			// Thời gian chờ giữa các tin nhắn (từ Interval của bot hoặc mặc định 12-25s)
			baseInterval := bot.Interval
			if baseInterval <= 0 {
				baseInterval = 15
			}
			// Jitter ngẫu nhiên từ -3s đến +5s
			jitter := r.Intn(9) - 3
			sleepDuration := time.Duration(baseInterval+jitter) * time.Second
			if sleepDuration < 5*time.Second {
				sleepDuration = 5 * time.Second
			}

			select {
			case <-ch:
				log.Printf("⏹️ [BOT RUNNER] Dừng chạy Bot trong phòng live '%s'", key)
				return
			case <-time.After(sleepDuration):
			}

			// Nếu bot có danh sách câu thoại mẫu
			if len(bot.Messages) > 0 {
				msgIdx := r.Intn(len(bot.Messages))
				text := strings.TrimSpace(bot.Messages[msgIdx])
				if text != "" {
					botRole := bot.Role
					if botRole == "" {
						botRole = "user"
					}

					chatMsg := ChatMessage{
						ID:        primitive.NewObjectID(),
						StreamKey: key,
						Username:  bot.Name,
						Role:      botRole,
						Message:   text,
						Type:      "chat",
						CreatedAt: time.Now(),
					}

					// Lưu vào MongoDB
					go saveChatMessage(chatMsg)

					// Broadcast qua WebSocket tới tất cả người xem trong phòng
					out := WSOutboundMessage{
						Type: "chat",
						Data: &chatMsg,
					}
					if ownerBytes, err := json.Marshal(out); err == nil {
						maskedMsg := chatMsg
						maskedMsg.Message = maskPhoneNumbers(maskedMsg.Message)
						maskedOut := WSOutboundMessage{Type: "chat", Data: &maskedMsg}
						if publicBytes, marshalErr := json.Marshal(maskedOut); marshalErr == nil {
							globalChatHub.broadcast <- broadcastEvent{streamKey: key, message: publicBytes, ownerMessage: ownerBytes}
						}
					}

					log.Printf("🤖 [BOT CHAT] [%s] %s: %s", key, bot.Name, text)
				}
			}

			// 25% xác suất bot thả reaction cảm xúc ngẫu nhiên để phòng live sinh động
			if r.Float32() < 0.25 {
				emojis := []string{"❤️", "🔥", "👏", "🎉", "💯", "⭐"}
				emoji := emojis[r.Intn(len(emojis))]
				out := WSOutboundMessage{
					Type:   "reaction",
					Emoji:  emoji,
					Sender: bot.Name,
				}
				if b, err := json.Marshal(out); err == nil {
					globalChatHub.broadcast <- broadcastEvent{streamKey: key, message: b}
				}
			}
		}
	}(streamKey, bots, stopCh)
}

// StopBots dừng tất cả bot đang chạy trong phòng live
func (m *BotRunnerManager) StopBots(streamKey string) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if stopCh, exists := m.runners[streamKey]; exists {
		close(stopCh)
		delete(m.runners, streamKey)
		log.Printf("⏹️ [BOT RUNNER] Đã nhận lệnh dừng Bot cho phòng '%s'", streamKey)
	}
}

// IsRunning kiểm tra xem phòng có bot đang chạy hay không
func (m *BotRunnerManager) IsRunning(streamKey string) bool {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	_, exists := m.runners[streamKey]
	return exists
}

// cleanMockBots xóa bỏ các Bot mẫu mock data để dữ liệu Bot trong DB chỉ bao gồm các Bot do Admin cấu hình thật
func cleanMockBots() {
	if botsColl == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res, err := botsColl.DeleteMany(ctx, bson.M{
		"name": bson.M{"$in": []string{"Minh Thư 🌸", "Hoàng Long 🔥", "Phương Thảo ✨", "Phương Thảo 💖", "Quốc Bảo ⚡", "Lan Anh 9x", "Lan Anh 9x 🛍️"}},
	})
	if err == nil && res.DeletedCount > 0 {
		log.Printf("🧹 [CLEANUP] Đã xóa %d bot mẫu mock data khỏi MongoDB", res.DeletedCount)
	}
}

// seedDefaultBots giữ lại tương thích, tự động dọn dẹp mock data
func seedDefaultBots() {
	cleanMockBots()
}

// ==================== SYSTEM ADMIN BOT HANDLERS ====================

// sysadminBotsHandler quản lý CRUD Bot dành riêng cho SystemAdmin
// GET /api/sysadmin/bots - Lấy danh sách bot
// POST /api/sysadmin/bots - Tạo bot mới
// PUT /api/sysadmin/bots - Cập nhật bot
// DELETE /api/sysadmin/bots?id=xxx - Xóa bot
func sysadminBotsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	claims, err := getUserFromAuthHeader(r)
	if err != nil || claims.Role != "systemadmin" {
		http.Error(w, `{"error":"Chỉ có SystemAdmin mới có quyền quản lý Bot hệ thống"}`, http.StatusForbidden)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	switch r.Method {
	case http.MethodGet:
		cursor, err := botsColl.Find(ctx, bson.M{}, options.Find().SetSort(bson.M{"created_at": -1}))
		if err != nil {
			http.Error(w, `{"error":"Lỗi tải danh sách bot"}`, http.StatusInternalServerError)
			return
		}
		defer cursor.Close(ctx)

		bots := make([]ChatBot, 0)
		_ = cursor.All(ctx, &bots)
		json.NewEncoder(w).Encode(bots)

	case http.MethodPost:
		limitRequestBody(w, r, SmallJSONMaxBodyBytes)
		var req struct {
			Name     string   `json:"name"`
			Avatar   string   `json:"avatar"`
			Role     string   `json:"role"`
			Messages []string `json:"messages"`
			Interval int      `json:"interval"`
			IsActive bool     `json:"is_active"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":"Dữ liệu không hợp lệ"}`, http.StatusBadRequest)
			return
		}

		name := strings.TrimSpace(req.Name)
		if name == "" {
			http.Error(w, `{"error":"Tên bot không được để trống"}`, http.StatusBadRequest)
			return
		}

		// Lọc các câu thoại không rỗng
		cleanMessages := make([]string, 0)
		for _, m := range req.Messages {
			trimmed := strings.TrimSpace(m)
			if trimmed != "" {
				cleanMessages = append(cleanMessages, trimmed)
			}
		}

		interval := req.Interval
		if interval <= 0 {
			interval = 15
		}

		avatar := strings.TrimSpace(req.Avatar)
		if avatar == "" {
			avatar = "🤖"
		}

		role := strings.TrimSpace(req.Role)
		if role == "" {
			role = "user"
		}

		newBot := ChatBot{
			ID:        primitive.NewObjectID(),
			Name:      name,
			Avatar:    avatar,
			Role:      role,
			Messages:  cleanMessages,
			Interval:  interval,
			IsActive:  true,
			CreatedBy: claims.Username,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}

		_, err := botsColl.InsertOne(ctx, newBot)
		if err != nil {
			http.Error(w, `{"error":"Lỗi tạo bot vào cơ sở dữ liệu"}`, http.StatusInternalServerError)
			return
		}

		recordAccessLog(claims.Username, claims.Role, "create_bot", getClientIP(r), fmt.Sprintf("Tạo mới bot tương tác '%s' (%d câu chat)", name, len(cleanMessages)))
		json.NewEncoder(w).Encode(newBot)

	case http.MethodPut:
		limitRequestBody(w, r, SmallJSONMaxBodyBytes)
		var req struct {
			ID       string   `json:"id"`
			Name     string   `json:"name"`
			Avatar   string   `json:"avatar"`
			Role     string   `json:"role"`
			Messages []string `json:"messages"`
			Interval int      `json:"interval"`
			IsActive bool     `json:"is_active"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":"Dữ liệu không hợp lệ"}`, http.StatusBadRequest)
			return
		}

		botObjID, err := primitive.ObjectIDFromHex(req.ID)
		if err != nil {
			http.Error(w, `{"error":"ID bot không hợp lệ"}`, http.StatusBadRequest)
			return
		}

		cleanMessages := make([]string, 0)
		for _, m := range req.Messages {
			trimmed := strings.TrimSpace(m)
			if trimmed != "" {
				cleanMessages = append(cleanMessages, trimmed)
			}
		}

		interval := req.Interval
		if interval <= 0 {
			interval = 15
		}

		update := bson.M{
			"$set": bson.M{
				"name":       strings.TrimSpace(req.Name),
				"avatar":     strings.TrimSpace(req.Avatar),
				"role":       strings.TrimSpace(req.Role),
				"messages":   cleanMessages,
				"interval":   interval,
				"is_active":  req.IsActive,
				"updated_at": time.Now(),
			},
		}

		_, err = botsColl.UpdateOne(ctx, bson.M{"_id": botObjID}, update)
		if err != nil {
			http.Error(w, `{"error":"Lỗi cập nhật bot"}`, http.StatusInternalServerError)
			return
		}

		recordAccessLog(claims.Username, claims.Role, "update_bot", getClientIP(r), fmt.Sprintf("Cập nhật bot '%s'", req.Name))
		json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "message": "Cập nhật bot thành công"})

	case http.MethodDelete:
		idStr := r.URL.Query().Get("id")
		botObjID, err := primitive.ObjectIDFromHex(idStr)
		if err != nil {
			http.Error(w, `{"error":"ID bot không hợp lệ"}`, http.StatusBadRequest)
			return
		}

		_, err = botsColl.DeleteOne(ctx, bson.M{"_id": botObjID})
		if err != nil {
			http.Error(w, `{"error":"Lỗi xóa bot"}`, http.StatusInternalServerError)
			return
		}

		recordAccessLog(claims.Username, claims.Role, "delete_bot", getClientIP(r), fmt.Sprintf("Xóa bot ID '%s'", idStr))
		json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "message": "Đã xóa bot thành công"})

	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

// ==================== ADMIN STREAMER BOT HANDLERS ====================

// adminAvailableBotsHandler trả về danh sách bot đang hoạt động để Admin chọn
// GET /api/admin/bots
func adminAvailableBotsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	claims, err := getUserFromAuthHeader(r)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "Yêu cầu đăng nhập để xem danh sách Bot"})
		return
	}
	if claims.Role != "admin" && claims.Role != "systemadmin" {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"error": "Quyền truy cập bị từ chối: Chỉ Quản trị viên mới được xem danh sách Bot"})
		return
	}

	if botsColl == nil {
		json.NewEncoder(w).Encode([]ChatBot{})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cursor, err := botsColl.Find(ctx, bson.M{"is_active": true}, options.Find().SetSort(bson.M{"name": 1}))
	if err != nil {
		http.Error(w, `{"error":"Lỗi tải danh sách bot"}`, http.StatusInternalServerError)
		return
	}
	defer cursor.Close(ctx)

	bots := make([]ChatBot, 0)
	_ = cursor.All(ctx, &bots)
	json.NewEncoder(w).Encode(bots)
}

// adminRoomBotsHandler cho phép Admin xem hoặc chọn tối đa 5 bot và bật/tắt vào phòng live
// GET /api/admin/room-bots?streamKey=xxx
// POST /api/admin/room-bots
func adminRoomBotsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	claims, err := getUserFromAuthHeader(r)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "Yêu cầu đăng nhập để cấu hình bot"})
		return
	}
	if claims.Role != "admin" && claims.Role != "systemadmin" {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"error": "Chỉ tài khoản Admin mới có quyền chọn Bot vào phòng live"})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	switch r.Method {
	case http.MethodGet:
		streamKey := strings.TrimSpace(r.URL.Query().Get("streamKey"))
		if streamKey == "" {
			http.Error(w, `{"error":"streamKey is required"}`, http.StatusBadRequest)
			return
		}

		// Kiểm tra quyền sở hữu phòng nếu là admin thường (chống IDOR)
		if !canAdminManageStreamOrSession(ctx, claims, streamKey, "") {
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{"error": "Quyền truy cập bị từ chối: Bạn không sở hữu phòng live này"})
			return
		}

		var assign RoomBotAssignment
		if roomBotsColl != nil {
			_ = roomBotsColl.FindOne(ctx, bson.M{"stream_key": streamKey}).Decode(&assign)
		}

		isRunning := globalBotManager.IsRunning(streamKey)

		// Lấy chi tiết các bot đã chọn
		selectedBots := make([]ChatBot, 0)
		if len(assign.BotIDs) > 0 && botsColl != nil {
			cursor, _ := botsColl.Find(ctx, bson.M{"_id": bson.M{"$in": assign.BotIDs}})
			if cursor != nil {
				_ = cursor.All(ctx, &selectedBots)
				cursor.Close(ctx)
			}
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"stream_key":    streamKey,
			"bot_ids":       assign.BotIDs,
			"selected_bots": selectedBots,
			"is_running":    isRunning,
			"max_allowed":   5,
		})

	case http.MethodPost:
		limitRequestBody(w, r, SmallJSONMaxBodyBytes)
		var req struct {
			StreamKey string   `json:"stream_key"`
			BotIDs    []string `json:"bot_ids"` // Tối đa 5 bot
			IsRunning bool     `json:"is_running"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":"Dữ liệu không hợp lệ"}`, http.StatusBadRequest)
			return
		}

		streamKey := strings.TrimSpace(req.StreamKey)
		if streamKey == "" {
			http.Error(w, `{"error":"stream_key không được để trống"}`, http.StatusBadRequest)
			return
		}

		// RÀNG BUỘC QUAN TRỌNG: KIỂM TRA QUYỀN SỞ HỮU PHÒNG LIVE (CHỐNG IDOR)
		if !canAdminManageStreamOrSession(ctx, claims, streamKey, "") {
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{"error": "Quyền truy cập bị từ chối: Bạn không có quyền gán bot vào phòng của người khác"})
			return
		}

		// RÀNG BUỘC: TỐI ĐA 5 CON BOT
		if len(req.BotIDs) > 5 {
			http.Error(w, `{"error":"⛔ Mỗi phòng livestream chỉ được phép chọn tối đa 5 bot tương tác!"}`, http.StatusBadRequest)
			return
		}

		botObjIDs := make([]primitive.ObjectID, 0)
		for _, idStr := range req.BotIDs {
			objID, errID := primitive.ObjectIDFromHex(idStr)
			if errID != nil {
				http.Error(w, `{"error":"bot_id không hợp lệ"}`, http.StatusBadRequest)
				return
			}
			botObjIDs = append(botObjIDs, objID)
		}

		// Lưu cấu hình vào MongoDB
		if roomBotsColl != nil {
			upsertOpt := options.Update().SetUpsert(true)
			_, err := roomBotsColl.UpdateOne(ctx,
				bson.M{"stream_key": streamKey},
				bson.M{
					"$set": bson.M{
						"stream_key": streamKey,
						"admin_user": claims.Username,
						"bot_ids":    botObjIDs,
						"is_running": req.IsRunning,
						"updated_at": time.Now(),
					},
				},
				upsertOpt,
			)
			if err != nil {
				http.Error(w, `{"error":"Lỗi lưu cấu hình bot phòng live"}`, http.StatusInternalServerError)
				return
			}
		}

		// Điều khiển luồng chạy bot
		if req.IsRunning && len(botObjIDs) > 0 {
			botsToRun := make([]ChatBot, 0)
			if botsColl != nil {
				cursor, _ := botsColl.Find(ctx, bson.M{
					"_id":       bson.M{"$in": botObjIDs},
					"is_active": true,
				})
				if cursor != nil {
					_ = cursor.All(ctx, &botsToRun)
					cursor.Close(ctx)
				}
			}

			globalBotManager.StartBots(streamKey, botsToRun)
			recordAccessLog(claims.Username, claims.Role, "start_bots", getClientIP(r), fmt.Sprintf("Bật %d bot tương tác vào phòng '%s'", len(botsToRun), streamKey))
		} else {
			globalBotManager.StopBots(streamKey)
			recordAccessLog(claims.Username, claims.Role, "stop_bots", getClientIP(r), fmt.Sprintf("Dừng bot tương tác trong phòng '%s'", streamKey))
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":    true,
			"stream_key": streamKey,
			"bot_count":  len(botObjIDs),
			"is_running": globalBotManager.IsRunning(streamKey),
			"message":    fmt.Sprintf("Đã cập nhật cấu hình (%d/5 bot, đang %s)", len(botObjIDs), map[bool]string{true: "chạy", false: "dừng"}[req.IsRunning]),
		})

	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}
