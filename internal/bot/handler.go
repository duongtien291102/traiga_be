package bot

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/options"

	"livestream-be/internal/model"
	"livestream-be/internal/security/limiter"
	"livestream-be/internal/store"
)

// Handler xử lý các HTTP endpoints quản trị bot và gán bot vào phòng live.
type Handler struct {
	GetStore        func() *store.Store
	GetUser         func(r *http.Request) (*model.JWTClaims, error)
	CanManageRoom   func(ctx context.Context, claims *model.JWTClaims, streamKey string) bool
	RecordAccessLog func(username, role, action, ip, details string)
	Manager         *RunnerManager
}

// NewHandler tạo một Handler bot mới.
func NewHandler(
	getStore func() *store.Store,
	getUser func(r *http.Request) (*model.JWTClaims, error),
	canManageRoom func(ctx context.Context, claims *model.JWTClaims, streamKey string) bool,
	recordAccessLog func(username, role, action, ip, details string),
	manager *RunnerManager,
) *Handler {
	return &Handler{
		GetStore:        getStore,
		GetUser:         getUser,
		CanManageRoom:   canManageRoom,
		RecordAccessLog: recordAccessLog,
		Manager:         manager,
	}
}

// CleanMockBots dọn dẹp các bot mẫu mock data khỏi MongoDB.
func (h *Handler) CleanMockBots() {
	var st *store.Store
	if h.GetStore != nil {
		st = h.GetStore()
	}
	if st == nil || st.Bots == nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	mockNames := []string{
		"Minh Thư 🌸", "Hoàng Long 🔥", "Phương Thảo ✨",
		"Phương Thảo 💖", "Quốc Bảo ⚡", "Lan Anh 9x", "Lan Anh 9x 🛍️",
	}

	res, err := st.Bots.DeleteMany(ctx, bson.M{
		"name": bson.M{"$in": mockNames},
	})
	if err == nil && res.DeletedCount > 0 {
		log.Printf("🧹 [CLEANUP] Đã xóa %d bot mẫu mock data khỏi MongoDB", res.DeletedCount)
	}
}

// SysadminBots xử lý CRUD Bot dành riêng cho SystemAdmin.
// GET /api/sysadmin/bots - Lấy danh sách bot
// POST /api/sysadmin/bots - Tạo bot mới
// PUT /api/sysadmin/bots - Cập nhật bot
// DELETE /api/sysadmin/bots?id=xxx - Xóa bot
func (h *Handler) SysadminBots(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if h.GetUser == nil {
		http.Error(w, `{"error":"Chỉ có SystemAdmin mới có quyền quản lý Bot hệ thống"}`, http.StatusForbidden)
		return
	}

	claims, err := h.GetUser(r)
	if err != nil || claims.Role != "systemadmin" {
		http.Error(w, `{"error":"Chỉ có SystemAdmin mới có quyền quản lý Bot hệ thống"}`, http.StatusForbidden)
		return
	}

	var st *store.Store
	if h.GetStore != nil {
		st = h.GetStore()
	}
	if st == nil || st.Bots == nil {
		http.Error(w, `{"error":"Cơ sở dữ liệu chưa sẵn sàng"}`, http.StatusServiceUnavailable)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	switch r.Method {
	case http.MethodGet:
		cursor, err := st.Bots.Find(ctx, bson.M{}, options.Find().SetSort(bson.M{"created_at": -1}))
		if err != nil {
			http.Error(w, `{"error":"Lỗi tải danh sách bot"}`, http.StatusInternalServerError)
			return
		}
		defer cursor.Close(ctx)

		bots := make([]model.ChatBot, 0)
		_ = cursor.All(ctx, &bots)
		_ = json.NewEncoder(w).Encode(bots)

	case http.MethodPost:
		limiter.LimitRequestBody(w, r, limiter.SmallJSONMaxBodyBytes)
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

		newBot := model.ChatBot{
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

		_, err := st.Bots.InsertOne(ctx, newBot)
		if err != nil {
			http.Error(w, `{"error":"Lỗi tạo bot vào cơ sở dữ liệu"}`, http.StatusInternalServerError)
			return
		}

		if h.RecordAccessLog != nil {
			h.RecordAccessLog(claims.Username, claims.Role, "create_bot", limiter.GetClientIP(r), fmt.Sprintf("Tạo mới bot tương tác '%s' (%d câu chat)", name, len(cleanMessages)))
		}
		_ = json.NewEncoder(w).Encode(newBot)

	case http.MethodPut:
		limiter.LimitRequestBody(w, r, limiter.SmallJSONMaxBodyBytes)
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

		_, err = st.Bots.UpdateOne(ctx, bson.M{"_id": botObjID}, update)
		if err != nil {
			http.Error(w, `{"error":"Lỗi cập nhật bot"}`, http.StatusInternalServerError)
			return
		}

		if h.RecordAccessLog != nil {
			h.RecordAccessLog(claims.Username, claims.Role, "update_bot", limiter.GetClientIP(r), fmt.Sprintf("Cập nhật bot '%s'", req.Name))
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "message": "Cập nhật bot thành công"})

	case http.MethodDelete:
		idStr := r.URL.Query().Get("id")
		botObjID, err := primitive.ObjectIDFromHex(idStr)
		if err != nil {
			http.Error(w, `{"error":"ID bot không hợp lệ"}`, http.StatusBadRequest)
			return
		}

		_, err = st.Bots.DeleteOne(ctx, bson.M{"_id": botObjID})
		if err != nil {
			http.Error(w, `{"error":"Lỗi xóa bot"}`, http.StatusInternalServerError)
			return
		}

		if h.RecordAccessLog != nil {
			h.RecordAccessLog(claims.Username, claims.Role, "delete_bot", limiter.GetClientIP(r), fmt.Sprintf("Xóa bot ID '%s'", idStr))
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "message": "Đã xóa bot thành công"})

	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

// AdminAvailableBots trả về danh sách bot đang hoạt động để Admin chọn.
// GET /api/admin/bots
func (h *Handler) AdminAvailableBots(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	if h.GetUser == nil {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "Yêu cầu đăng nhập để xem danh sách Bot"})
		return
	}

	claims, err := h.GetUser(r)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "Yêu cầu đăng nhập để xem danh sách Bot"})
		return
	}
	if claims.Role != "admin" && claims.Role != "systemadmin" {
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "Quyền truy cập bị từ chối: Chỉ Quản trị viên mới được xem danh sách Bot"})
		return
	}

	var st *store.Store
	if h.GetStore != nil {
		st = h.GetStore()
	}
	if st == nil || st.Bots == nil {
		_ = json.NewEncoder(w).Encode([]model.ChatBot{})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cursor, err := st.Bots.Find(ctx, bson.M{"is_active": true}, options.Find().SetSort(bson.M{"name": 1}))
	if err != nil {
		http.Error(w, `{"error":"Lỗi tải danh sách bot"}`, http.StatusInternalServerError)
		return
	}
	defer cursor.Close(ctx)

	bots := make([]model.ChatBot, 0)
	_ = cursor.All(ctx, &bots)
	_ = json.NewEncoder(w).Encode(bots)
}

// AdminRoomBots cho phép Admin xem hoặc chọn tối đa 5 bot và bật/tắt vào phòng live.
// GET /api/admin/room-bots?streamKey=xxx
// POST /api/admin/room-bots
func (h *Handler) AdminRoomBots(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if h.GetUser == nil {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "Yêu cầu đăng nhập để cấu hình bot"})
		return
	}

	claims, err := h.GetUser(r)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "Yêu cầu đăng nhập để cấu hình bot"})
		return
	}
	if claims.Role != "admin" && claims.Role != "systemadmin" {
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "Chỉ tài khoản Admin mới có quyền chọn Bot vào phòng live"})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var st *store.Store
	if h.GetStore != nil {
		st = h.GetStore()
	}

	switch r.Method {
	case http.MethodGet:
		streamKey := strings.TrimSpace(r.URL.Query().Get("streamKey"))
		if streamKey == "" {
			http.Error(w, `{"error":"streamKey is required"}`, http.StatusBadRequest)
			return
		}

		if h.CanManageRoom != nil && !h.CanManageRoom(ctx, claims, streamKey) {
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Quyền truy cập bị từ chối: Bạn không sở hữu phòng live này"})
			return
		}

		var assign model.RoomBotAssignment
		if st != nil && st.RoomBots != nil {
			_ = st.RoomBots.FindOne(ctx, bson.M{"stream_key": streamKey}).Decode(&assign)
		}

		isRunning := false
		if h.Manager != nil {
			isRunning = h.Manager.IsRunning(streamKey)
		}

		selectedBots := make([]model.ChatBot, 0)
		if len(assign.BotIDs) > 0 && st != nil && st.Bots != nil {
			cursor, _ := st.Bots.Find(ctx, bson.M{"_id": bson.M{"$in": assign.BotIDs}})
			if cursor != nil {
				_ = cursor.All(ctx, &selectedBots)
				cursor.Close(ctx)
			}
		}

		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"stream_key":    streamKey,
			"bot_ids":       assign.BotIDs,
			"selected_bots": selectedBots,
			"is_running":    isRunning,
			"max_allowed":   5,
		})

	case http.MethodPost:
		limiter.LimitRequestBody(w, r, limiter.SmallJSONMaxBodyBytes)
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

		if h.CanManageRoom != nil && !h.CanManageRoom(ctx, claims, streamKey) {
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Quyền truy cập bị từ chối: Bạn không có quyền gán bot vào phòng của người khác"})
			return
		}

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

		if st != nil && st.RoomBots != nil {
			upsertOpt := options.Update().SetUpsert(true)
			_, err := st.RoomBots.UpdateOne(ctx,
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

		isRunningNow := false
		if req.IsRunning && len(botObjIDs) > 0 {
			botsToRun := make([]model.ChatBot, 0)
			if st != nil && st.Bots != nil {
				cursor, _ := st.Bots.Find(ctx, bson.M{
					"_id":       bson.M{"$in": botObjIDs},
					"is_active": true,
				})
				if cursor != nil {
					_ = cursor.All(ctx, &botsToRun)
					cursor.Close(ctx)
				}
			}

			if h.Manager != nil {
				h.Manager.StartBots(streamKey, botsToRun)
				isRunningNow = h.Manager.IsRunning(streamKey)
			}
			if h.RecordAccessLog != nil {
				h.RecordAccessLog(claims.Username, claims.Role, "start_bots", limiter.GetClientIP(r), fmt.Sprintf("Bật %d bot tương tác vào phòng '%s'", len(botsToRun), streamKey))
			}
		} else {
			if h.Manager != nil {
				h.Manager.StopBots(streamKey)
				isRunningNow = h.Manager.IsRunning(streamKey)
			}
			if h.RecordAccessLog != nil {
				h.RecordAccessLog(claims.Username, claims.Role, "stop_bots", limiter.GetClientIP(r), fmt.Sprintf("Dừng bot tương tác trong phòng '%s'", streamKey))
			}
		}

		statusText := "dừng"
		if req.IsRunning {
			statusText = "chạy"
		}

		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success":    true,
			"stream_key": streamKey,
			"bot_count":  len(botObjIDs),
			"is_running": isRunningNow,
			"message":    fmt.Sprintf("Đã cập nhật cấu hình (%d/5 bot, đang %s)", len(botObjIDs), statusText),
		})

	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}
