package dvr

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"path/filepath"
	"regexp"
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

// Handler quản lý các endpoint liên quan đến DVR và Replays
type Handler struct {
	GetStore               func() *store.Store
	GetJwtSecret           func() []byte
	VerifySRSWebhookSecret func(r *http.Request) bool
}

// NewHandler khởi tạo mới DVR Handler
func NewHandler(
	getStore func() *store.Store,
	getJwtSecret func() []byte,
	verifySRSWebhookSecret func(r *http.Request) bool,
) *Handler {
	return &Handler{
		GetStore:               getStore,
		GetJwtSecret:           getJwtSecret,
		VerifySRSWebhookSecret: verifySRSWebhookSecret,
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

// CanAdminManageStreamOrSession kiểm tra quyền sở hữu StreamKey/Session để chống lỗ hổng IDOR giữa các Admin
func (h *Handler) CanAdminManageStreamOrSession(ctx context.Context, claims *model.JWTClaims, streamKey string, streamer string) bool {
	if claims == nil {
		return false
	}
	if claims.Role == "systemadmin" {
		return true
	}
	if claims.Role != "admin" {
		return false
	}

	callerObjID, errID := primitive.ObjectIDFromHex(claims.UserID)

	st := h.GetStore()
	if st != nil && st.Keys != nil && streamKey != "" {
		var keyDoc model.StreamKey
		if err := st.Keys.FindOne(ctx, bson.M{"key": streamKey}).Decode(&keyDoc); err == nil {
			if errID == nil && keyDoc.UserID != nil && *keyDoc.UserID == callerObjID {
				return true
			}
			if keyDoc.UserID == nil && strings.EqualFold(keyDoc.Streamer, claims.Username) {
				return true
			}
			return false
		}
	}

	// Kiểm tra theo username của Admin
	if streamKey != "" && strings.EqualFold(streamKey, claims.Username) {
		return true
	}
	if streamer != "" && strings.EqualFold(streamer, claims.Username) {
		return true
	}
	return false
}

// DVR nhận webhook on_dvr từ SRS khi file .mp4 ghi hình hoàn tất
// POST /auth/dvr
func (h *Handler) DVR(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	if h.VerifySRSWebhookSecret != nil && !h.VerifySRSWebhookSecret(r) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"code":403,"error":"Forbidden: Invalid SRS Webhook Secret"}`)
		return
	}

	srsBaseURL, err := SRSHTTPBaseURL()
	if err != nil {
		log.Printf("[SRS DVR CONFIG ERROR] Không nhận webhook DVR vì thiếu URL lưu trữ: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]string{"code": "1", "error": "Recording storage is not configured"})
		return
	}

	limiter.LimitRequestBody(w, r, limiter.SmallJSONMaxBodyBytes)
	var payload model.SRSAuthPayload
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, `{"error":"Payload too large or invalid"}`, http.StatusRequestEntityTooLarge)
		return
	}
	if len(body) > 0 {
		if err := json.Unmarshal(body, &payload); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"code": "1", "error": "Invalid DVR webhook payload"})
			return
		}
	}

	streamKey := strings.TrimSpace(payload.Stream)
	if streamKey == "" {
		streamKey = strings.TrimSpace(payload.Name)
	}
	rawFile := strings.TrimSpace(payload.File)
	baseName := filepath.Base(rawFile)
	appName := strings.TrimSpace(payload.App)
	if appName == "" {
		appName = "live"
	}
	if streamKey == "" || baseName == "." || baseName == string(filepath.Separator) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"code": "1", "error": "DVR webhook is missing stream or file"})
		return
	}

	relativeReplayPath := fmt.Sprintf("/record/%s/%s", appName, baseName)
	vpsRecordURL := MakeSRSRecordURL(srsBaseURL, relativeReplayPath)

	log.Printf("🎬 [SRS DVR RECORDED] Phiên live '%s' đã xuất file: %s", streamKey, relativeReplayPath)

	st := h.GetStore()
	if st != nil && st.IsReady() && st.Sessions != nil && streamKey != "" && baseName != "" {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
			defer cancel()
			now := time.Now()

			// Tìm tiêu đề của Stream Key
			roomTitle := fmt.Sprintf("Phiên Live %s", streamKey)
			streamerName := "Chủ Trại"
			if st.Keys != nil {
				var kDoc model.StreamKey
				if errK := st.Keys.FindOne(ctx, bson.M{"key": streamKey}).Decode(&kDoc); errK == nil {
					if kDoc.Title != "" {
						roomTitle = kDoc.Title
					}
					if kDoc.Streamer != "" {
						streamerName = kDoc.Streamer
					}
				}
			}

			// Chỉ gắn file DVR vào phiên còn live hoặc phiên mới kết thúc; tránh gắn file cũ
			// vào phiên tiếp theo khi cùng stream key phát lại nhanh.
			var targetSession model.LiveSession
			opts := options.FindOne().SetSort(bson.M{"started_at": -1})
			errFind := st.Sessions.FindOne(ctx, bson.M{
				"stream_key": streamKey,
				"started_at": bson.M{"$gte": now.Add(-24 * time.Hour)},
				"$or": []bson.M{
					{"status": "live"},
					{"status": "ended", "replay_url": bson.M{"$exists": false}},
					{"status": "ended", "replay_url": ""},
				},
			}, opts).Decode(&targetSession)

			if errFind != nil {
				// Nếu chưa có session thì tạo mới
				targetSession = model.LiveSession{
					ID:           primitive.NewObjectID(),
					StreamKey:    streamKey,
					Streamer:     streamerName,
					Title:        roomTitle,
					App:          appName,
					Status:       "ended",
					StartedAt:    now,
					EndedAt:      &now,
					ReplayURL:    relativeReplayPath,
					RecordStatus: "ready",
				}
				if _, errInsert := st.Sessions.InsertOne(ctx, targetSession); errInsert != nil {
					log.Printf("[SRS DVR SESSION ERROR] Không lưu được session cho file %s: %v", relativeReplayPath, errInsert)
					return
				}
			} else {
				updateFields := bson.M{
					"replay_url":    relativeReplayPath,
					"record_status": "ready",
				}
				if targetSession.EndedAt == nil {
					endedAt := now
					updateFields["ended_at"] = endedAt
					updateFields["status"] = "ended"
					updateFields["duration_seconds"] = max(int64(0), int64(now.Sub(targetSession.StartedAt).Seconds()))
				}
				if targetSession.Title == "" {
					updateFields["title"] = roomTitle
				}
				if _, errUpdate := st.Sessions.UpdateOne(ctx, bson.M{"_id": targetSession.ID}, bson.M{"$set": updateFields}); errUpdate != nil {
					log.Printf("[SRS DVR SESSION ERROR] Không cập nhật được session %s: %v", targetSession.ID.Hex(), errUpdate)
					return
				}
			}

			// Nếu đã cấu hình Google Drive OAuth2 -> Tự động đẩy file .mp4 lên Google Drive
			if DriveAutoUploadConfigured() {
				keyPart := regexp.MustCompile(`[^a-zA-Z0-9_-]+`).ReplaceAllString(streamKey, "_")
				if keyPart == "" {
					keyPart = "live"
				}
				driveFileName := fmt.Sprintf("TraiGa_%s_%s.mp4", keyPart, targetSession.StartedAt.Format("20060102_150405"))
				log.Printf("☁️ [GOOGLE DRIVE UPLOAD] Đang tải '%s' lên Google Drive...", driveFileName)

				fileID, previewURL, errUp := UploadStreamToGoogleDrive(driveFileName, vpsRecordURL)
				if errUp != nil {
					log.Printf("⚠️ [GOOGLE DRIVE UPLOAD ERROR] Không thể tải '%s' lên Google Drive: %v", driveFileName, errUp)
					ctxStatus, cancelStatus := context.WithTimeout(context.Background(), 10*time.Second)
					_, _ = st.Sessions.UpdateOne(ctxStatus, bson.M{"_id": targetSession.ID}, bson.M{"$set": bson.M{"record_status": "ready"}})
					cancelStatus()
					return
				}

				ctxUp, cancelUp := context.WithTimeout(context.Background(), 10*time.Second)
				_, errUpdate := st.Sessions.UpdateOne(ctxUp, bson.M{"_id": targetSession.ID}, bson.M{
					"$set": bson.M{
						"drive_file_id": fileID,
						"replay_url":    previewURL,
						"record_status": "uploaded_drive",
					},
				})
				cancelUp()
				if errUpdate != nil {
					log.Printf("[GOOGLE DRIVE METADATA ERROR] File đã upload nhưng không cập nhật được phiên %s: %v", targetSession.ID.Hex(), errUpdate)
					return
				}
				log.Printf("✅ [GOOGLE DRIVE UPLOAD SUCCESS] Đã lưu lên Google Drive: %s", previewURL)
			}
		}()
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `{"code":0}`)
}

// ArchiveReplay lưu trữ vĩnh viễn file DVR cục bộ lên Google Drive.
// POST /api/sessions/archive
func (h *Handler) ArchiveReplay(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	claims, err := h.getUser(r)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "Vui lòng đăng nhập để lưu trữ video"})
		return
	}
	if claims.Role != "admin" && claims.Role != "systemadmin" {
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "Chỉ chủ kênh mới có thể lưu trữ video"})
		return
	}
	if !DriveAutoUploadConfigured() {
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "Chưa cấu hình Google Drive để lưu trữ video lâu dài"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 35*time.Minute)
	defer cancel()
	objID, err := primitive.ObjectIDFromHex(strings.TrimSpace(r.URL.Query().Get("id")))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "Mã phiên live không hợp lệ"})
		return
	}

	st := h.GetStore()
	if st == nil || st.Sessions == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "Cơ sở dữ liệu chưa sẵn sàng"})
		return
	}
	var session model.LiveSession
	if err := st.Sessions.FindOne(ctx, bson.M{"_id": objID}).Decode(&session); err != nil {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "Không tìm thấy phiên live"})
		return
	}
	if !h.CanAdminManageStreamOrSession(ctx, claims, session.StreamKey, session.Streamer) {
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "Bạn không có quyền lưu trữ video của kênh này"})
		return
	}
	if session.RecordStatus == "uploaded_drive" && session.DriveFileID != "" {
		_ = json.NewEncoder(w).Encode(map[string]string{"message": "Video đã được lưu trữ trên Google Drive", "replay_url": session.ReplayURL})
		return
	}
	if !strings.HasPrefix(session.ReplayURL, "/record/") || strings.Contains(session.ReplayURL, "..") {
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "Không tìm thấy bản ghi DVR trên máy chủ để lưu trữ"})
		return
	}
	if session.RecordStatus != "ready" {
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "Bản ghi chưa sẵn sàng để lưu trữ"})
		return
	}

	baseURL, err := SRSHTTPBaseURL()
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "Chưa cấu hình địa chỉ SRS để truy xuất bản ghi"})
		return
	}
	keyPart := regexp.MustCompile(`[^a-zA-Z0-9_-]+`).ReplaceAllString(session.StreamKey, "_")
	if keyPart == "" {
		keyPart = "live"
	}
	fileName := fmt.Sprintf("TraiGa_%s_%s.mp4", keyPart, session.StartedAt.Format("20060102_150405"))
	driveID, previewURL, err := UploadStreamToGoogleDrive(fileName, MakeSRSRecordURL(baseURL, session.ReplayURL))
	if err != nil {
		log.Printf("[REPLAY ARCHIVE] Lưu trữ phiên %s thất bại: %v", objID.Hex(), err)
		w.WriteHeader(http.StatusBadGateway)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "Không thể tải video lên Google Drive. Hãy thử lại khi bản ghi còn trên máy chủ."})
		return
	}
	if _, err := st.Sessions.UpdateOne(ctx, bson.M{"_id": objID}, bson.M{"$set": bson.M{"drive_file_id": driveID, "replay_url": previewURL, "record_status": "uploaded_drive"}}); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "Video đã tải lên nhưng không thể cập nhật hồ sơ lưu trữ"})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]string{"message": "Đã lưu trữ video trên Google Drive", "replay_url": previewURL})
}

// ListReplays trả về danh sách các phiên live có video xem lại (Public cho toàn bộ người xem trên web).
// GET /api/replays
func (h *Handler) ListReplays(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	st := h.GetStore()
	if st == nil || !st.IsReady() || st.Sessions == nil {
		_ = json.NewEncoder(w).Encode([]interface{}{})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	filter := bson.M{
		"replay_url": bson.M{"$exists": true, "$ne": ""},
	}
	if streamKey := strings.TrimSpace(r.URL.Query().Get("streamKey")); streamKey != "" {
		filter["stream_key"] = streamKey
	}

	opts := options.Find().SetSort(bson.M{"started_at": -1}).SetLimit(30)
	cursor, err := st.Sessions.Find(ctx, filter, opts)
	if err != nil {
		_ = json.NewEncoder(w).Encode([]interface{}{})
		return
	}
	defer cursor.Close(ctx)

	var sessions []model.LiveSession
	_ = cursor.All(ctx, &sessions)

	type PublicReplayItem struct {
		ID              primitive.ObjectID `json:"id"`
		StreamKey       string             `json:"stream_key"`
		Streamer        string             `json:"streamer"`
		Title           string             `json:"title"`
		StartedAt       time.Time          `json:"started_at"`
		EndedAt         *time.Time         `json:"ended_at,omitempty"`
		DurationSeconds int64              `json:"duration_seconds"`
		ReplayURL       string             `json:"replay_url"`
		DriveFileID     string             `json:"drive_file_id,omitempty"`
		RecordStatus    string             `json:"record_status,omitempty"`
	}

	result := make([]PublicReplayItem, 0, len(sessions))
	for _, s := range sessions {
		title := s.Title
		if title == "" {
			title = fmt.Sprintf("Phiên Live Trại Gà %s", s.Streamer)
		}
		result = append(result, PublicReplayItem{
			ID:              s.ID,
			StreamKey:       s.StreamKey,
			Streamer:        s.Streamer,
			Title:           title,
			StartedAt:       s.StartedAt,
			EndedAt:         s.EndedAt,
			DurationSeconds: s.DurationSeconds,
			ReplayURL:       s.ReplayURL,
			DriveFileID:     s.DriveFileID,
			RecordStatus:    s.RecordStatus,
		})
	}

	_ = json.NewEncoder(w).Encode(result)
}

// ManageSessionReplay cho phép Admin / SystemAdmin gắn link Google Drive hoặc xóa bản ghi xem lại.
// POST/PUT/DELETE /api/sessions/replay
func (h *Handler) ManageSessionReplay(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodPost && r.Method != http.MethodPut && r.Method != http.MethodDelete {
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
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "Chỉ Admin hoặc SystemAdmin mới có quyền quản lý video xem lại"})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	st := h.GetStore()
	ready := st != nil && st.IsReady() && st.Sessions != nil

	switch r.Method {
	case http.MethodPost, http.MethodPut:
		limiter.LimitRequestBody(w, r, limiter.SmallJSONMaxBodyBytes)
		var req struct {
			SessionID string `json:"session_id"`
			StreamKey string `json:"stream_key"`
			Title     string `json:"title"`
			ReplayURL string `json:"replay_url"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Dữ liệu không hợp lệ hoặc vượt quá giới hạn dung lượng"})
			return
		}

		normalizedURL, driveID := NormalizeReplayURL(req.ReplayURL)
		if normalizedURL == "" {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Vui lòng nhập đường dẫn Google Drive hoặc link video hợp lệ (http/https)"})
			return
		}

		streamKey := strings.TrimSpace(req.StreamKey)
		if streamKey != "" && !h.CanAdminManageStreamOrSession(ctx, claims, streamKey, "") {
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Quyền truy cập bị từ chối: Bạn không sở hữu phòng live này"})
			return
		}

		if !ready {
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Database chưa sẵn sàng"})
			return
		}

		recordStatus := "ready"
		if driveID != "" || strings.Contains(normalizedURL, "drive.google.com") {
			recordStatus = "uploaded_drive"
		}

		// Nếu có truyền session_id -> Kiểm tra quyền sở hữu (IDOR) rồi mới cập nhật vào session đó
		if strings.TrimSpace(req.SessionID) != "" {
			objID, errID := primitive.ObjectIDFromHex(strings.TrimSpace(req.SessionID))
			if errID != nil {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "session_id không hợp lệ"})
				return
			}

			var targetSession model.LiveSession
			if errFind := st.Sessions.FindOne(ctx, bson.M{"_id": objID}).Decode(&targetSession); errFind != nil {
				w.WriteHeader(http.StatusNotFound)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "Không tìm thấy phiên live"})
				return
			}

			if !h.CanAdminManageStreamOrSession(ctx, claims, targetSession.StreamKey, targetSession.Streamer) {
				w.WriteHeader(http.StatusForbidden)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "Quyền truy cập bị từ chối: Bạn không sở hữu bản ghi phiên live này"})
				return
			}

			updateFields := bson.M{
				"replay_url":    normalizedURL,
				"drive_file_id": driveID,
				"record_status": recordStatus,
			}
			if strings.TrimSpace(req.Title) != "" {
				updateFields["title"] = strings.TrimSpace(req.Title)
			}
			_, errUp := st.Sessions.UpdateOne(ctx, bson.M{"_id": objID}, bson.M{"$set": updateFields})
			if errUp != nil {
				w.WriteHeader(http.StatusInternalServerError)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "Không thể cập nhật phiên live"})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{
				"message":    "Đã cập nhật video xem lại thành công",
				"replay_url": normalizedURL,
			})
			return
		}

		// Nếu không có session_id -> Tạo mới 1 bản ghi phát lại
		if streamKey == "" {
			streamKey = claims.Username
		}
		title := strings.TrimSpace(req.Title)
		if title == "" {
			title = fmt.Sprintf("Phát lại phiên live (%s)", time.Now().Format("02/01/2006"))
		}
		now := time.Now()
		newSession := model.LiveSession{
			ID:           primitive.NewObjectID(),
			StreamKey:    streamKey,
			Streamer:     claims.Username,
			Title:        title,
			App:          "live",
			Status:       "ended",
			StartedAt:    now,
			EndedAt:      &now,
			ReplayURL:    normalizedURL,
			DriveFileID:  driveID,
			RecordStatus: recordStatus,
		}
		_, errIns := st.Sessions.InsertOne(ctx, newSession)
		if errIns != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Lỗi lưu video phát lại"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"message": "Đã thêm video xem lại thành công",
			"session": newSession,
		})

	case http.MethodDelete:
		sessionID := strings.TrimSpace(r.URL.Query().Get("id"))
		objID, errID := primitive.ObjectIDFromHex(sessionID)
		if errID != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "ID không hợp lệ"})
			return
		}

		if !ready {
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Database chưa sẵn sàng"})
			return
		}

		var targetSession model.LiveSession
		if errFind := st.Sessions.FindOne(ctx, bson.M{"_id": objID}).Decode(&targetSession); errFind != nil {
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Không tìm thấy phiên live"})
			return
		}

		if !h.CanAdminManageStreamOrSession(ctx, claims, targetSession.StreamKey, targetSession.Streamer) {
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Quyền truy cập bị từ chối: Bạn không có quyền xóa bản ghi của người khác"})
			return
		}

		_, _ = st.Sessions.UpdateOne(ctx, bson.M{"_id": objID}, bson.M{
			"$unset": bson.M{
				"replay_url":    "",
				"drive_file_id": "",
				"record_status": "",
			},
		})
		_ = json.NewEncoder(w).Encode(map[string]string{"message": "Đã xóa video phát lại khỏi phiên này"})
	}
}
