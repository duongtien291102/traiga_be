package stream

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/options"

	"livestream-be/internal/auth"
	"livestream-be/internal/model"
	"livestream-be/internal/security/limiter"
	"livestream-be/internal/store"
)

// Handler quản lý xác thực luồng phát, quản lý khóa phát và phiên live.
type Handler struct {
	GetStore                       func() *store.Store
	GetJwtSecret                   func() []byte
	VerifySRSWebhookSecret         func(r *http.Request) bool
	PublishSecretMatches           func(provided, expectedHash string) bool
	ExtractSecretFromParam         func(param string) string
	HydratePublishSecret           func(key *model.StreamKey) error
	StreamKeyForStorage            func(key model.StreamKey) (model.StreamKey, error)
	FindStreamKeyByID              func(ctx context.Context, id primitive.ObjectID) (model.StreamKey, error)
	InsertStreamKey                func(ctx context.Context, key model.StreamKey) (model.StreamKey, error)
	RecordAccessLog                func(username, role, action, ip, details string)
	ResetRoomChat                  func(room string)
	StopBots                       func(room string)
	CanAdminManageStreamOrSession func(ctx context.Context, claims *model.JWTClaims, streamKey, streamer string) bool
}

// NewHandler tạo mới Stream Handler
func NewHandler(
	getStore func() *store.Store,
	getJwtSecret func() []byte,
	verifySRSWebhookSecret func(r *http.Request) bool,
	publishSecretMatches func(provided, expectedHash string) bool,
	extractSecretFromParam func(param string) string,
	hydratePublishSecret func(key *model.StreamKey) error,
	streamKeyForStorage func(key model.StreamKey) (model.StreamKey, error),
	findStreamKeyByID func(ctx context.Context, id primitive.ObjectID) (model.StreamKey, error),
	insertStreamKey func(ctx context.Context, key model.StreamKey) (model.StreamKey, error),
	recordAccessLog func(username, role, action, ip, details string),
	resetRoomChat func(room string),
	stopBots func(room string),
	canAdminManageStreamOrSession func(ctx context.Context, claims *model.JWTClaims, streamKey, streamer string) bool,
) *Handler {
	return &Handler{
		GetStore:                       getStore,
		GetJwtSecret:                   getJwtSecret,
		VerifySRSWebhookSecret:         verifySRSWebhookSecret,
		PublishSecretMatches:           publishSecretMatches,
		ExtractSecretFromParam:         extractSecretFromParam,
		HydratePublishSecret:           hydratePublishSecret,
		StreamKeyForStorage:            streamKeyForStorage,
		FindStreamKeyByID:              findStreamKeyByID,
		InsertStreamKey:                insertStreamKey,
		RecordAccessLog:                recordAccessLog,
		ResetRoomChat:                  resetRoomChat,
		StopBots:                       stopBots,
		CanAdminManageStreamOrSession: canAdminManageStreamOrSession,
	}
}

func (h *Handler) getSecret() []byte {
	if h.GetJwtSecret != nil {
		return h.GetJwtSecret()
	}
	return nil
}

func (h *Handler) getUser(r *http.Request) (*model.JWTClaims, error) {
	return auth.GetUserFromAuthHeader(r, h.getSecret())
}

// EnsureAdminStreamKeys tự động cấp khóa luồng cho Admin nếu chưa có hoặc cập nhật khóa cũ
func (h *Handler) EnsureAdminStreamKeys(ctx context.Context, user model.User) ([]model.StreamKey, error) {
	st := h.GetStore()
	if st == nil || st.Keys == nil {
		return nil, fmt.Errorf("stream key database is unavailable")
	}

	filter := bson.M{"$or": []bson.M{{"user_id": user.ID}, {"streamer": user.FullName}, {"streamer": user.Username}}}
	cursor, err := st.Keys.Find(ctx, filter)
	if err != nil {
		return nil, err
	}
	keys := make([]model.StreamKey, 0)
	if err := cursor.All(ctx, &keys); err != nil {
		_ = cursor.Close(ctx)
		return nil, err
	}
	_ = cursor.Close(ctx)

	for i := range keys {
		if keys[i].PublishSecret == "" && h.HydratePublishSecret != nil {
			if err := h.HydratePublishSecret(&keys[i]); err != nil {
				return nil, fmt.Errorf("không thể mở khóa phát của phòng %s: %w", keys[i].ID.Hex(), err)
			}
		}
		if strings.EqualFold(keys[i].Key, user.Username) {
			newKey, err := GenerateStreamKey()
			if err != nil {
				return nil, err
			}
			storedKey := keys[i]
			if h.StreamKeyForStorage != nil {
				storedKey, err = h.StreamKeyForStorage(keys[i])
				if err != nil {
					return nil, err
				}
			}
			if _, err := st.Keys.UpdateOne(ctx, bson.M{"_id": keys[i].ID}, bson.M{"$set": bson.M{
				"key":                 newKey,
				"publish_secret_enc":  storedKey.PublishSecretEncrypted,
				"publish_secret_hash": storedKey.PublishSecretHash,
			}}); err != nil {
				return nil, err
			}
			keys[i].Key = newKey
		}
	}

	if len(keys) == 0 {
		newKey, err := GenerateStreamKey()
		if err != nil {
			return nil, err
		}
		key := model.StreamKey{
			Key:       newKey,
			Title:     fmt.Sprintf("Kênh %s", user.FullName),
			Streamer:  user.FullName,
			UserID:    &user.ID,
			IsActive:  true,
			CreatedAt: time.Now(),
		}
		if h.InsertStreamKey != nil {
			key, err = h.InsertStreamKey(ctx, key)
			if err != nil {
				return nil, err
			}
		} else {
			storedKey := key
			if h.StreamKeyForStorage != nil {
				storedKey, err = h.StreamKeyForStorage(key)
				if err != nil {
					return nil, err
				}
			}
			res, err := st.Keys.InsertOne(ctx, storedKey)
			if err != nil {
				return nil, err
			}
			key = storedKey
			key.ID = res.InsertedID.(primitive.ObjectID)
		}
		keys = append(keys, key)
	}
	return keys, nil
}

// RecordLiveSession ghi nhận phiên live mới và chốt các phiên cũ chưa đóng
func (h *Handler) RecordLiveSession(streamKey, app, clientIP string) {
	st := h.GetStore()
	if st == nil || !st.IsReady() || st.Sessions == nil {
		return
	}

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		streamerName := "Admin"
		if st.Keys != nil {
			var kDoc model.StreamKey
			if err := st.Keys.FindOne(ctx, bson.M{"key": streamKey}).Decode(&kDoc); err == nil && kDoc.Streamer != "" {
				streamerName = kDoc.Streamer
			}
		}

		now := time.Now()
		// Đóng các session 'live' cũ của cùng stream key này
		_, _ = st.Sessions.UpdateMany(ctx,
			bson.M{"stream_key": streamKey, "status": "live"},
			bson.M{"$set": bson.M{"status": "ended", "ended_at": now}},
		)

		session := model.LiveSession{
			StreamKey: streamKey,
			Streamer:  streamerName,
			App:       app,
			ClientIP:  clientIP,
			Status:    "live",
			StartedAt: now,
		}
		_, _ = st.Sessions.InsertOne(ctx, session)
		if h.RecordAccessLog != nil {
			h.RecordAccessLog(streamerName, "admin", "start_stream", clientIP, fmt.Sprintf("Bắt đầu phát sóng luồng '%s' (App: %s)", streamKey, app))
		}

		// Mỗi lần live mới bắt đầu: Phát lệnh reset kênh chat cho client
		if h.ResetRoomChat != nil {
			h.ResetRoomChat(streamKey)
		}
	}()
}

// Auth xử lý webhook xác thực từ SRS hoặc Nginx-RTMP
// POST /auth
func (h *Handler) Auth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	verifyWebhook := h.VerifySRSWebhookSecret
	if verifyWebhook == nil {
		verifyWebhook = VerifySRSWebhookSecret
	}
	if !verifyWebhook(r) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"code":403,"error":"Forbidden: Invalid SRS Webhook Secret"}`)
		return
	}

	limiter.LimitRequestBody(w, r, limiter.SmallJSONMaxBodyBytes)
	var streamKey, publishSecret, clientAddr, appName, param string
	contentType := r.Header.Get("Content-Type")

	// 1. Parse JSON từ SRS Media Server
	if strings.Contains(contentType, "application/json") {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, `{"error":"Payload too large"}`, http.StatusRequestEntityTooLarge)
			return
		}
		if len(body) > 0 {
			var payload model.SRSAuthPayload
			if err := json.Unmarshal(body, &payload); err == nil {
				streamKey = strings.TrimSpace(payload.Stream)
				if streamKey == "" {
					streamKey = strings.TrimSpace(payload.Name)
				}
				clientAddr = payload.IP
				appName = payload.App
				param = payload.Param
			}
		}
	}

	// 2. Parse Form-data từ Nginx-RTMP
	if streamKey == "" {
		if err := r.ParseForm(); err == nil {
			streamKey = strings.TrimSpace(r.FormValue("stream"))
			if streamKey == "" {
				streamKey = strings.TrimSpace(r.FormValue("name"))
			}
			if clientAddr == "" {
				clientAddr = r.FormValue("addr")
			}
			if appName == "" {
				appName = r.FormValue("app")
			}
			param = r.FormValue("param")
			publishSecret = r.FormValue("publish_secret")
		} else if strings.Contains(err.Error(), "http: request body too large") {
			http.Error(w, `{"error":"Payload too large"}`, http.StatusRequestEntityTooLarge)
			return
		}
	}

	if clientAddr == "" {
		clientAddr = limiter.GetClientIP(r)
	}
	if publishSecret == "" && h.ExtractSecretFromParam != nil {
		publishSecret = h.ExtractSecretFromParam(param)
	}

	st := h.GetStore()
	ctx := r.Context()

	// Kiểm tra tính hợp lệ và đang hoạt động trong MongoDB
	if streamKey != "" && VerifyInternalABRStream(ctx, st, appName, streamKey, clientAddr) {
		log.Printf("[AUTH SUCCESS] Internal ABR rendition allowed - Room rendition: '%s'", streamKey)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"code":0}`)
		return
	}

	if streamKey != "" && appName != "abr" && VerifyStreamKey(ctx, st, streamKey, publishSecret, h.PublishSecretMatches) {
		log.Printf("[AUTH SUCCESS] Stream allowed (MongoDB verified) - Room: '%s' | App: '%s' | Client: %s", streamKey, appName, clientAddr)
		h.RecordLiveSession(streamKey, appName, clientAddr)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"code":0}`)
		return
	}

	log.Printf("[AUTH FAILED] Stream denied - Room: '%s' (không hợp lệ hoặc publish secret sai) | Client: %s", streamKey, clientAddr)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	fmt.Fprint(w, `{"code":403,"error":"Forbidden: Invalid or Disabled Stream Key"}`)
}

// Unpublish xử lý webhook khi luồng live dừng (từ SRS on_unpublish)
// POST /auth/unpublish
func (h *Handler) Unpublish(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	verifyWebhook := h.VerifySRSWebhookSecret
	if verifyWebhook == nil {
		verifyWebhook = VerifySRSWebhookSecret
	}
	if !verifyWebhook(r) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"code":403,"error":"Forbidden: Invalid SRS Webhook Secret"}`)
		return
	}

	limiter.LimitRequestBody(w, r, limiter.SmallJSONMaxBodyBytes)
	var streamKey, clientAddr, appName string
	contentType := r.Header.Get("Content-Type")

	if strings.Contains(contentType, "application/json") {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, `{"error":"Payload too large"}`, http.StatusRequestEntityTooLarge)
			return
		}
		if len(body) > 0 {
			var payload model.SRSAuthPayload
			if err := json.Unmarshal(body, &payload); err == nil {
				streamKey = strings.TrimSpace(payload.Stream)
				if streamKey == "" {
					streamKey = strings.TrimSpace(payload.Name)
				}
				clientAddr = payload.IP
				appName = payload.App
			}
		}
	}

	if streamKey == "" {
		if err := r.ParseForm(); err == nil {
			streamKey = strings.TrimSpace(r.FormValue("stream"))
			if streamKey == "" {
				streamKey = strings.TrimSpace(r.FormValue("name"))
			}
			if clientAddr == "" {
				clientAddr = r.FormValue("addr")
			}
			if appName == "" {
				appName = r.FormValue("app")
			}
		}
	}

	if clientAddr == "" {
		clientAddr = limiter.GetClientIP(r)
	}
	if appName == "abr" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"code":0}`)
		return
	}

	log.Printf("⏹️ [STREAM UNPUBLISH] Luồng live kết thúc - Key: '%s' | App: '%s' | Client: %s", streamKey, appName, clientAddr)

	st := h.GetStore()
	if st != nil && st.IsReady() && st.Sessions != nil && streamKey != "" {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			var latest model.LiveSession
			opts := options.FindOne().SetSort(bson.M{"started_at": -1})
			err := st.Sessions.FindOne(ctx, bson.M{"stream_key": streamKey, "status": "live"}, opts).Decode(&latest)
			if err == nil {
				now := time.Now()
				duration := int64(now.Sub(latest.StartedAt).Seconds())
				if duration < 0 {
					duration = 0
				}
				_, _ = st.Sessions.UpdateOne(ctx, bson.M{"_id": latest.ID}, bson.M{
					"$set": bson.M{
						"status":           "ended",
						"ended_at":         now,
						"duration_seconds": duration,
					},
				})
				if h.RecordAccessLog != nil {
					h.RecordAccessLog(latest.Streamer, "admin", "stop_stream", clientAddr, fmt.Sprintf("Kết thúc luồng '%s'. Thời lượng: %d giây", streamKey, duration))
				}
			}
			// Dừng bot tương tác trong phòng live khi streamer kết thúc live
			if h.StopBots != nil {
				h.StopBots(streamKey)
			}

			// Luồng kết thúc: Phát lệnh reset kênh chat cho client
			if h.ResetRoomChat != nil {
				h.ResetRoomChat(streamKey)
			}
		}()
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `{"code":0}`)
}

// Keys quản lý danh sách và tạo/xóa Stream Keys
// GET/POST/DELETE /api/keys
func (h *Handler) Keys(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		claims, err := h.getUser(r)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Yêu cầu đăng nhập để truy cập danh sách Stream Keys"})
			return
		}
		if claims.Role != "admin" && claims.Role != "systemadmin" {
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Quyền truy cập bị từ chối: Chỉ Quản trị viên mới được xem Stream Keys"})
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		var filter bson.M
		if claims.Role == "systemadmin" {
			filter = bson.M{}
		} else {
			objID, errID := primitive.ObjectIDFromHex(claims.UserID)
			if errID == nil {
				filter = bson.M{
					"$or": []bson.M{
						{"user_id": objID},
						{"streamer": claims.Username},
					},
				}
			} else {
				filter = bson.M{"streamer": claims.Username}
			}
		}

		st := h.GetStore()
		if st == nil || st.Keys == nil {
			_ = json.NewEncoder(w).Encode([]model.StreamKey{})
			return
		}

		cursor, err := st.Keys.Find(ctx, filter)
		if err != nil {
			http.Error(w, `{"error":"Lỗi truy vấn"}`, http.StatusInternalServerError)
			return
		}
		defer cursor.Close(ctx)

		keys := make([]model.StreamKey, 0)
		_ = cursor.All(ctx, &keys)
		_ = json.NewEncoder(w).Encode(keys)

	case http.MethodPost:
		claims, err := h.getUser(r)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Yêu cầu đăng nhập"})
			return
		}
		if claims.Role != "admin" && claims.Role != "systemadmin" {
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Chỉ tài khoản Admin hoặc SystemAdmin mới có quyền tạo Stream Key"})
			return
		}

		limiter.LimitRequestBody(w, r, limiter.SmallJSONMaxBodyBytes)
		var req struct {
			Key           string `json:"key"`
			Title         string `json:"title"`
			Streamer      string `json:"streamer"`
			UserID        string `json:"user_id"`
			AdminUsername string `json:"admin_username"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":"Dữ liệu JSON không hợp lệ"}`, http.StatusBadRequest)
			return
		}

		cleanKey := strings.ToLower(strings.TrimSpace(req.Key))
		if cleanKey == "" {
			http.Error(w, `{"error":"Khóa luồng không được để trống"}`, http.StatusBadRequest)
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		var newKey model.StreamKey
		newKey.Key = cleanKey
		newKey.Title = strings.TrimSpace(req.Title)
		if newKey.Title == "" {
			newKey.Title = fmt.Sprintf("Kênh %s", cleanKey)
		}

		st := h.GetStore()
		if st == nil || st.Users == nil || st.Keys == nil {
			http.Error(w, `{"error":"Cơ sở dữ liệu chưa sẵn sàng"}`, http.StatusServiceUnavailable)
			return
		}

		if claims.Role == "systemadmin" {
			var targetAdmin model.User
			var found bool

			if req.UserID != "" {
				if objID, errID := primitive.ObjectIDFromHex(req.UserID); errID == nil {
					if errFind := st.Users.FindOne(ctx, bson.M{"_id": objID, "role": "admin"}).Decode(&targetAdmin); errFind == nil {
						found = true
					}
				}
			}
			if !found && req.AdminUsername != "" {
				if errFind := st.Users.FindOne(ctx, bson.M{"username": strings.ToLower(strings.TrimSpace(req.AdminUsername)), "role": "admin"}).Decode(&targetAdmin); errFind == nil {
					found = true
				}
			}
			if !found && req.Streamer != "" {
				if errFind := st.Users.FindOne(ctx, bson.M{"username": strings.ToLower(strings.TrimSpace(req.Streamer)), "role": "admin"}).Decode(&targetAdmin); errFind == nil {
					found = true
				}
			}
			if !found {
				_ = st.Users.FindOne(ctx, bson.M{"role": "admin"}).Decode(&targetAdmin)
			}

			if targetAdmin.ID != primitive.NilObjectID {
				newKey.UserID = &targetAdmin.ID
				newKey.Streamer = targetAdmin.FullName
				if newKey.Streamer == "" {
					newKey.Streamer = targetAdmin.Username
				}
			} else {
				newKey.Streamer = "Admin"
			}
		} else {
			objID, _ := primitive.ObjectIDFromHex(claims.UserID)
			newKey.UserID = &objID
			newKey.Streamer = claims.Username
		}
		newKey.IsActive = true
		newKey.CreatedAt = time.Now()

		if h.InsertStreamKey != nil {
			inserted, insertErr := h.InsertStreamKey(ctx, newKey)
			if insertErr != nil {
				w.WriteHeader(http.StatusConflict)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "Stream Key này đã tồn tại!"})
				return
			}
			newKey = inserted
		} else {
			res, err := st.Keys.InsertOne(ctx, newKey)
			if err != nil {
				w.WriteHeader(http.StatusConflict)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "Stream Key này đã tồn tại!"})
				return
			}
			newKey.ID = res.InsertedID.(primitive.ObjectID)
		}

		if h.RecordAccessLog != nil {
			h.RecordAccessLog(claims.Username, claims.Role, "create_key", limiter.GetClientIP(r),
				fmt.Sprintf("Tạo khóa luồng mới '%s' cho Streamer '%s'", newKey.Key, newKey.Streamer))
		}

		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(newKey)

	case http.MethodDelete:
		claims, err := h.getUser(r)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Yêu cầu đăng nhập để thực hiện thao tác"})
			return
		}
		if claims.Role != "admin" && claims.Role != "systemadmin" {
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Quyền truy cập bị từ chối: Chỉ Quản trị viên mới được xóa Stream Key"})
			return
		}

		keyParam := strings.TrimSpace(r.URL.Query().Get("key"))
		if keyParam == "" {
			http.Error(w, `{"error":"Thiếu tham số key"}`, http.StatusBadRequest)
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		st := h.GetStore()
		if st == nil || st.Keys == nil {
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Không tìm thấy khóa luồng"})
			return
		}

		var targetKey model.StreamKey
		errFind := st.Keys.FindOne(ctx, bson.M{"key": keyParam}).Decode(&targetKey)
		if errFind != nil {
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Không tìm thấy khóa luồng"})
			return
		}

		if claims.Role != "systemadmin" {
			callerObjID, errID := primitive.ObjectIDFromHex(claims.UserID)
			if errID != nil {
				w.WriteHeader(http.StatusForbidden)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "Quyền truy cập bị từ chối: ID người dùng không hợp lệ"})
				return
			}
			isOwner := targetKey.UserID != nil && *targetKey.UserID == callerObjID
			if !isOwner {
				w.WriteHeader(http.StatusForbidden)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "Quyền truy cập bị từ chối: Bạn không sở hữu Stream Key này"})
				return
			}
		}

		res, err := st.Keys.DeleteOne(ctx, bson.M{"_id": targetKey.ID})
		if err != nil || res.DeletedCount == 0 {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Không thể xóa khóa"})
			return
		}

		if h.RecordAccessLog != nil {
			h.RecordAccessLog(claims.Username, claims.Role, "delete_key", limiter.GetClientIP(r),
				fmt.Sprintf("Xóa khóa luồng '%s'", keyParam))
		}

		_ = json.NewEncoder(w).Encode(map[string]string{"message": "Đã xóa Stream Key thành công"})

	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

// RevealPublishSecret trả về khóa phát giải mã cho chủ sở hữu
// GET /api/keys/reveal-secret
func (h *Handler) RevealPublishSecret(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store, max-age=0")
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	claims, err := h.getUser(r)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "Yêu cầu đăng nhập"})
		return
	}
	if claims.Role != "admin" && claims.Role != "systemadmin" {
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "Chỉ Admin mới được xem khóa phát"})
		return
	}

	st := h.GetStore()
	if st == nil || st.Keys == nil {
		http.Error(w, `{"error":"Cơ sở dữ liệu chưa sẵn sàng"}`, http.StatusServiceUnavailable)
		return
	}

	id, err := primitive.ObjectIDFromHex(strings.TrimSpace(r.URL.Query().Get("id")))
	if err != nil {
		http.Error(w, `{"error":"ID khóa không hợp lệ"}`, http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	var targetKey model.StreamKey
	if h.FindStreamKeyByID != nil {
		targetKey, err = h.FindStreamKeyByID(ctx, id)
	} else {
		err = st.Keys.FindOne(ctx, bson.M{"_id": id}).Decode(&targetKey)
	}
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "Không tìm thấy khóa phát"})
		return
	}

	if claims.Role != "systemadmin" {
		callerID, errID := primitive.ObjectIDFromHex(claims.UserID)
		ownsKey := errID == nil && targetKey.UserID != nil && *targetKey.UserID == callerID
		if !ownsKey && targetKey.UserID == nil {
			ownsKey = strings.EqualFold(targetKey.Streamer, claims.Username)
		}
		if !ownsKey {
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Bạn không sở hữu khóa phát này"})
			return
		}
	}

	if h.HydratePublishSecret != nil {
		if err := h.HydratePublishSecret(&targetKey); err != nil {
			http.Error(w, `{"error":"Không thể mở khóa phát"}`, http.StatusInternalServerError)
			return
		}
	}

	if h.RecordAccessLog != nil {
		h.RecordAccessLog(claims.Username, claims.Role, "reveal_publish_secret", limiter.GetClientIP(r), fmt.Sprintf("Xem khóa phát của phòng '%s'", targetKey.Key))
	}
	_ = json.NewEncoder(w).Encode(map[string]string{"publish_secret": targetKey.PublishSecret})
}

// ToggleKey bật hoặc tắt Stream Key
// PATCH/POST /api/keys/toggle
func (h *Handler) ToggleKey(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPatch && r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	claims, err := h.getUser(r)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "Yêu cầu đăng nhập"})
		return
	}
	if claims.Role != "admin" && claims.Role != "systemadmin" {
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "Chỉ Quản trị viên (Admin hoặc SystemAdmin) mới có quyền bật/tắt Key"})
		return
	}

	limiter.LimitRequestBody(w, r, limiter.SmallJSONMaxBodyBytes)
	var req struct {
		Key      string `json:"key"`
		IsActive bool   `json:"is_active"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Dữ liệu không hợp lệ"}`, http.StatusBadRequest)
		return
	}

	req.Key = strings.TrimSpace(req.Key)
	if req.Key == "" {
		http.Error(w, `{"error":"Thiếu tham số key"}`, http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	st := h.GetStore()
	if st != nil && st.Keys != nil {
		var targetKey model.StreamKey
		if errFind := st.Keys.FindOne(ctx, bson.M{"key": req.Key}).Decode(&targetKey); errFind != nil {
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Không tìm thấy khóa luồng"})
			return
		}
		if claims.Role != "systemadmin" {
			callerObjID, errID := primitive.ObjectIDFromHex(claims.UserID)
			if errID != nil || targetKey.UserID == nil || *targetKey.UserID != callerObjID {
				w.WriteHeader(http.StatusForbidden)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "Quyền truy cập bị từ chối: Bạn không sở hữu Stream Key này"})
				return
			}
		}

		_, err = st.Keys.UpdateOne(ctx, bson.M{"_id": targetKey.ID}, bson.M{"$set": bson.M{"is_active": req.IsActive}})
		if err != nil {
			http.Error(w, `{"error":"Lỗi cập nhật"}`, http.StatusInternalServerError)
			return
		}
	} else if h.CanAdminManageStreamOrSession != nil {
		if !h.CanAdminManageStreamOrSession(ctx, claims, req.Key, "") {
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Quyền truy cập bị từ chối: Bạn không sở hữu Stream Key này"})
			return
		}
	}

	if h.RecordAccessLog != nil {
		h.RecordAccessLog(claims.Username, claims.Role, "toggle_key", limiter.GetClientIP(r),
			fmt.Sprintf("Cập nhật trạng thái khóa '%s' thành %v", req.Key, req.IsActive))
	}

	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"message":   "Cập nhật trạng thái thành công!",
		"key":       req.Key,
		"is_active": req.IsActive,
	})
}

// Sessions trả về lịch sử phiên live cho Admin hoặc SystemAdmin
// GET /api/sessions
func (h *Handler) Sessions(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	claims, err := h.getUser(r)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "Yêu cầu đăng nhập để truy cập lịch sử phiên live"})
		return
	}
	if claims.Role != "admin" && claims.Role != "systemadmin" {
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "Quyền truy cập bị từ chối: Chỉ Quản trị viên mới được xem lịch sử"})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var filter bson.M
	if claims.Role == "systemadmin" {
		filter = bson.M{}
	} else {
		filter = bson.M{
			"$or": []bson.M{
				{"streamer": claims.Username},
				{"stream_key": claims.Username},
			},
		}
	}

	st := h.GetStore()
	if st == nil || st.Sessions == nil {
		_ = json.NewEncoder(w).Encode([]model.LiveSession{})
		return
	}

	opts := options.Find().SetSort(bson.M{"started_at": -1}).SetLimit(50)
	cursor, err := st.Sessions.Find(ctx, filter, opts)
	if err != nil {
		http.Error(w, `{"error":"Lỗi truy vấn lịch sử"}`, http.StatusInternalServerError)
		return
	}
	defer cursor.Close(ctx)

	var sessions []model.LiveSession
	_ = cursor.All(ctx, &sessions)

	var safeSessions []model.LiveSession
	for _, s := range sessions {
		safeSessions = append(safeSessions, model.LiveSession{
			ID:              s.ID,
			StreamKey:       s.StreamKey,
			Streamer:        s.Streamer,
			Title:           s.Title,
			App:             s.App,
			ClientIP:        MaskIP(s.ClientIP),
			Status:          s.Status,
			StartedAt:       s.StartedAt,
			EndedAt:         s.EndedAt,
			DurationSeconds: s.DurationSeconds,
			ReplayURL:       s.ReplayURL,
			DriveFileID:     s.DriveFileID,
			RecordStatus:    s.RecordStatus,
		})
	}

	_ = json.NewEncoder(w).Encode(safeSessions)
}
