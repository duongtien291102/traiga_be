package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var driveFileIDRegex = regexp.MustCompile(`(?:/d/|id=)([a-zA-Z0-9_-]{15,})`)
var pureDriveIDRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]{20,}$`)

// normalizeReplayURL chuẩn hóa link Google Drive (share link -> /preview embed link) hoặc giữ nguyên link .mp4 hợp lệ.
// Chặn triệt để các URI scheme nguy hiểm (javascript:, data:, vbscript:, file:...) để phòng chống Stored XSS.
func normalizeReplayURL(raw string) (string, string) {
	clean := strings.TrimSpace(raw)
	if clean == "" {
		return "", ""
	}
	if matches := driveFileIDRegex.FindStringSubmatch(clean); len(matches) >= 2 {
		fileID := matches[1]
		return fmt.Sprintf("https://drive.google.com/file/d/%s/preview", fileID), fileID
	}
	// Nếu chỉ truyền thẳng Google Drive File ID (chỉ gồm chữ, số, _, - và >= 20 ký tự)
	if pureDriveIDRegex.MatchString(clean) {
		return fmt.Sprintf("https://drive.google.com/file/d/%s/preview", clean), clean
	}
	// Cho phép đường dẫn nội bộ /record/... (không chứa ..)
	if strings.HasPrefix(clean, "/record/") && !strings.Contains(clean, "..") {
		return clean, ""
	}
	// Chỉ cho phép URL có scheme http:// hoặc https:// hợp lệ
	parsed, err := url.Parse(clean)
	if err != nil || parsed.Host == "" {
		return "", ""
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "https" && scheme != "http" {
		return "", ""
	}
	return clean, ""
}

// getGoogleDriveAccessToken đổi Refresh Token lấy Access Token từ Google OAuth2
func getGoogleDriveAccessToken() (string, error) {
	clientID := strings.TrimSpace(os.Getenv("GOOGLE_DRIVE_CLIENT_ID"))
	clientSecret := strings.TrimSpace(os.Getenv("GOOGLE_DRIVE_CLIENT_SECRET"))
	refreshToken := strings.TrimSpace(os.Getenv("GOOGLE_DRIVE_REFRESH_TOKEN"))

	if clientID == "" || clientSecret == "" || refreshToken == "" {
		return "", fmt.Errorf("missing Google Drive OAuth2 credentials")
	}

	form := url.Values{}
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)
	form.Set("refresh_token", refreshToken)
	form.Set("grant_type", "refresh_token")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.PostForm("https://oauth2.googleapis.com/token", form)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("oauth2 token error (%d): %s", resp.StatusCode, string(body))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", err
	}
	if strings.TrimSpace(tokenResp.AccessToken) == "" {
		return "", fmt.Errorf("OAuth2 response did not contain an access token")
	}
	return tokenResp.AccessToken, nil
}

// uploadStreamToGoogleDrive tải luồng .mp4 từ SRS VPS và đẩy thẳng lên Google Drive qua Resumable Upload
func uploadStreamToGoogleDrive(displayName, vpsRecordURL string) (string, string, error) {
	accessToken, err := getGoogleDriveAccessToken()
	if err != nil {
		return "", "", err
	}

	folderID := strings.TrimSpace(os.Getenv("GOOGLE_DRIVE_FOLDER_ID"))

	// 1. Mở kết nối tải file .mp4 từ SRS VPS
	httpClient := &http.Client{Timeout: 30 * time.Minute}
	srcResp, err := httpClient.Get(vpsRecordURL)
	if err != nil {
		return "", "", fmt.Errorf("failed to fetch recording from VPS: %w", err)
	}
	defer srcResp.Body.Close()

	if srcResp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("VPS returned status %d for %s", srcResp.StatusCode, vpsRecordURL)
	}

	// 2. Khởi tạo phiên Resumable Upload trên Google Drive API v3
	meta := map[string]interface{}{
		"name":     displayName,
		"mimeType": "video/mp4",
	}
	if folderID != "" {
		meta["parents"] = []string{folderID}
	}
	metaBytes, _ := json.Marshal(meta)

	initReq, err := http.NewRequest(
		http.MethodPost,
		"https://www.googleapis.com/upload/drive/v3/files?uploadType=resumable",
		bytes.NewReader(metaBytes),
	)
	if err != nil {
		return "", "", err
	}
	initReq.Header.Set("Authorization", "Bearer "+accessToken)
	initReq.Header.Set("Content-Type", "application/json; charset=UTF-8")
	initReq.Header.Set("X-Upload-Content-Type", "video/mp4")
	if srcResp.ContentLength > 0 {
		initReq.Header.Set("X-Upload-Content-Length", fmt.Sprintf("%d", srcResp.ContentLength))
	}

	initResp, err := httpClient.Do(initReq)
	if err != nil {
		return "", "", err
	}
	defer initResp.Body.Close()

	if initResp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(initResp.Body)
		return "", "", fmt.Errorf("failed to initiate Drive resumable upload (%d): %s", initResp.StatusCode, string(b))
	}

	uploadURL := initResp.Header.Get("Location")
	if uploadURL == "" {
		return "", "", fmt.Errorf("missing Location header from Drive resumable upload")
	}

	// 3. Stream trực tiếp dữ liệu .mp4 từ VPS lên Google Drive (không lưu vào RAM/ổ đĩa Backend)
	putReq, err := http.NewRequest(http.MethodPut, uploadURL, srcResp.Body)
	if err != nil {
		return "", "", err
	}
	putReq.Header.Set("Content-Type", "video/mp4")
	if srcResp.ContentLength > 0 {
		putReq.ContentLength = srcResp.ContentLength
	}

	putResp, err := httpClient.Do(putReq)
	if err != nil {
		return "", "", fmt.Errorf("failed during Drive stream upload: %w", err)
	}
	defer putResp.Body.Close()

	if putResp.StatusCode != http.StatusOK && putResp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(putResp.Body)
		return "", "", fmt.Errorf("Drive upload failed (%d): %s", putResp.StatusCode, string(b))
	}

	var uploadedFile struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(putResp.Body).Decode(&uploadedFile); err != nil || uploadedFile.ID == "" {
		return "", "", fmt.Errorf("cannot decode Drive file ID: %v", err)
	}

	// 4. Mở quyền xem công khai (Anyone with link can view) để nhúng trình phát lên web
	permBody := []byte(`{"role":"reader","type":"anyone"}`)
	permReq, err := http.NewRequest(
		http.MethodPost,
		fmt.Sprintf("https://www.googleapis.com/drive/v3/files/%s/permissions", uploadedFile.ID),
		bytes.NewReader(permBody),
	)
	if err == nil {
		permReq.Header.Set("Authorization", "Bearer "+accessToken)
		permReq.Header.Set("Content-Type", "application/json")
		if permResp, errP := httpClient.Do(permReq); errP == nil {
			defer permResp.Body.Close()
			if permResp.StatusCode < http.StatusOK || permResp.StatusCode >= http.StatusMultipleChoices {
				body, _ := io.ReadAll(permResp.Body)
				return "", "", fmt.Errorf("Drive upload completed but sharing permission failed (%d): %s", permResp.StatusCode, string(body))
			}
		} else {
			return "", "", fmt.Errorf("Drive upload completed but sharing permission request failed: %w", errP)
		}
	} else {
		return "", "", err
	}

	previewURL := fmt.Sprintf("https://drive.google.com/file/d/%s/preview", uploadedFile.ID)
	return uploadedFile.ID, previewURL, nil
}

func srsHTTPBaseURL() (string, error) {
	baseURL := strings.TrimRight(strings.TrimSpace(os.Getenv("SRS_HTTP_URL")), "/")
	if baseURL == "" {
		return "", fmt.Errorf("SRS_HTTP_URL is not configured")
	}
	parsed, err := url.Parse(baseURL)
	if err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Host == "" {
		return "", fmt.Errorf("SRS_HTTP_URL must be an absolute http(s) URL")
	}
	return baseURL, nil
}

func makeSRSRecordURL(baseURL, replayPath string) string {
	return strings.TrimRight(baseURL, "/") + "/" + strings.TrimLeft(replayPath, "/")
}

func driveAutoUploadConfigured() bool {
	return strings.TrimSpace(os.Getenv("GOOGLE_DRIVE_CLIENT_ID")) != "" &&
		strings.TrimSpace(os.Getenv("GOOGLE_DRIVE_CLIENT_SECRET")) != "" &&
		strings.TrimSpace(os.Getenv("GOOGLE_DRIVE_REFRESH_TOKEN")) != ""
}

// canAdminManageStreamOrSession kiểm tra quyền sở hữu StreamKey/Session để chống lỗ hổng IDOR giữa các Admin
func canAdminManageStreamOrSession(ctx context.Context, claims *JWTClaims, streamKey string, streamer string) bool {
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

	// Nếu có kết nối keysColl, kiểm tra chủ sở hữu của streamKey
	if keysColl != nil && streamKey != "" {
		var keyDoc StreamKey
		if err := keysColl.FindOne(ctx, bson.M{"key": streamKey}).Decode(&keyDoc); err == nil {
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

// dvrHandler nhận webhook on_dvr từ SRS khi file .mp4 ghi hình hoàn tất
func dvrHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	if !verifySRSWebhookSecret(r) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"code":403,"error":"Forbidden: Invalid SRS Webhook Secret"}`)
		return
	}

	srsBaseURL, err := srsHTTPBaseURL()
	if err != nil {
		log.Printf("[SRS DVR CONFIG ERROR] Không nhận webhook DVR vì thiếu URL lưu trữ: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]string{"code": "1", "error": "Recording storage is not configured"})
		return
	}

	limitRequestBody(w, r, SmallJSONMaxBodyBytes)
	var payload SRSAuthPayload
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
	vpsRecordURL := makeSRSRecordURL(srsBaseURL, relativeReplayPath)

	log.Printf("🎬 [SRS DVR RECORDED] Phiên live '%s' đã xuất file: %s", streamKey, relativeReplayPath)

	mongoMutex.RLock()
	ready := isMongoReady
	coll := sessionsColl
	kColl := keysColl
	mongoMutex.RUnlock()

	if ready && coll != nil && streamKey != "" && baseName != "" {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
			defer cancel()
			now := time.Now()

			// Tìm tiêu đề của Stream Key
			roomTitle := fmt.Sprintf("Phiên Live %s", streamKey)
			streamerName := "Chủ Trại"
			if kColl != nil {
				var kDoc StreamKey
				if errK := kColl.FindOne(ctx, bson.M{"key": streamKey}).Decode(&kDoc); errK == nil {
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
			var targetSession LiveSession
			opts := options.FindOne().SetSort(bson.M{"started_at": -1})
			errFind := coll.FindOne(ctx, bson.M{
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
				targetSession = LiveSession{
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
				if _, errInsert := coll.InsertOne(ctx, targetSession); errInsert != nil {
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
				if _, errUpdate := coll.UpdateOne(ctx, bson.M{"_id": targetSession.ID}, bson.M{"$set": updateFields}); errUpdate != nil {
					log.Printf("[SRS DVR SESSION ERROR] Không cập nhật được session %s: %v", targetSession.ID.Hex(), errUpdate)
					return
				}
			}

			// Nếu đã cấu hình Google Drive OAuth2 -> Tự động đẩy file .mp4 lên Google Drive
			if driveAutoUploadConfigured() {
				keyPart := regexp.MustCompile(`[^a-zA-Z0-9_-]+`).ReplaceAllString(streamKey, "_")
				if keyPart == "" {
					keyPart = "live"
				}
				driveFileName := fmt.Sprintf("TraiGa_%s_%s.mp4", keyPart, targetSession.StartedAt.Format("20060102_150405"))
				log.Printf("☁️ [GOOGLE DRIVE UPLOAD] Đang tải '%s' lên Google Drive...", driveFileName)

				fileID, previewURL, errUp := uploadStreamToGoogleDrive(driveFileName, vpsRecordURL)
				if errUp != nil {
					log.Printf("⚠️ [GOOGLE DRIVE UPLOAD ERROR] Không thể tải '%s' lên Google Drive: %v", driveFileName, errUp)
					ctxStatus, cancelStatus := context.WithTimeout(context.Background(), 10*time.Second)
					_, _ = coll.UpdateOne(ctxStatus, bson.M{"_id": targetSession.ID}, bson.M{"$set": bson.M{"record_status": "ready"}})
					cancelStatus()
					return
				}

				ctxUp, cancelUp := context.WithTimeout(context.Background(), 10*time.Second)
				_, errUpdate := coll.UpdateOne(ctxUp, bson.M{"_id": targetSession.ID}, bson.M{
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

// archiveReplayHandler permanently stores a completed local DVR file in Drive.
func archiveReplayHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	claims, err := getUserFromAuthHeader(r)
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
	if !driveAutoUploadConfigured() {
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
	if sessionsColl == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "Cơ sở dữ liệu chưa sẵn sàng"})
		return
	}
	var session LiveSession
	if err := sessionsColl.FindOne(ctx, bson.M{"_id": objID}).Decode(&session); err != nil {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "Không tìm thấy phiên live"})
		return
	}
	if !canAdminManageStreamOrSession(ctx, claims, session.StreamKey, session.Streamer) {
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

	baseURL, err := srsHTTPBaseURL()
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
	driveID, previewURL, err := uploadStreamToGoogleDrive(fileName, makeSRSRecordURL(baseURL, session.ReplayURL))
	if err != nil {
		log.Printf("[REPLAY ARCHIVE] Lưu trữ phiên %s thất bại: %v", objID.Hex(), err)
		w.WriteHeader(http.StatusBadGateway)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "Không thể tải video lên Google Drive. Hãy thử lại khi bản ghi còn trên máy chủ."})
		return
	}
	if _, err := sessionsColl.UpdateOne(ctx, bson.M{"_id": objID}, bson.M{"$set": bson.M{"drive_file_id": driveID, "replay_url": previewURL, "record_status": "uploaded_drive"}}); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "Video đã tải lên nhưng không thể cập nhật hồ sơ lưu trữ"})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]string{"message": "Đã lưu trữ video trên Google Drive", "replay_url": previewURL})
}

// apiReplaysHandler trả về danh sách các phiên live có video xem lại (Public cho toàn bộ người xem trên web)
func apiReplaysHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	mongoMutex.RLock()
	ready := isMongoReady
	coll := sessionsColl
	mongoMutex.RUnlock()

	if !ready || coll == nil {
		json.NewEncoder(w).Encode([]interface{}{})
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
	cursor, err := coll.Find(ctx, filter, opts)
	if err != nil {
		json.NewEncoder(w).Encode([]interface{}{})
		return
	}
	defer cursor.Close(ctx)

	var sessions []LiveSession
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

	json.NewEncoder(w).Encode(result)
}

// apiSessionReplayManageHandler cho phép Admin / SystemAdmin gắn link Google Drive hoặc xóa bản ghi xem lại
func apiSessionReplayManageHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	claims, err := getUserFromAuthHeader(r)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "Yêu cầu đăng nhập"})
		return
	}
	if claims.Role != "admin" && claims.Role != "systemadmin" {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"error": "Chỉ Admin hoặc SystemAdmin mới có quyền quản lý video xem lại"})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	mongoMutex.RLock()
	ready := isMongoReady
	coll := sessionsColl
	mongoMutex.RUnlock()

	switch r.Method {
	case http.MethodPost, http.MethodPut:
		limitRequestBody(w, r, SmallJSONMaxBodyBytes)
		var req struct {
			SessionID string `json:"session_id"`
			StreamKey string `json:"stream_key"`
			Title     string `json:"title"`
			ReplayURL string `json:"replay_url"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "Dữ liệu không hợp lệ hoặc vượt quá giới hạn dung lượng"})
			return
		}

		normalizedURL, driveID := normalizeReplayURL(req.ReplayURL)
		if normalizedURL == "" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "Vui lòng nhập đường dẫn Google Drive hoặc link video hợp lệ (http/https)"})
			return
		}

		streamKey := strings.TrimSpace(req.StreamKey)
		if streamKey != "" && !canAdminManageStreamOrSession(ctx, claims, streamKey, "") {
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{"error": "Quyền truy cập bị từ chối: Bạn không sở hữu phòng live này"})
			return
		}

		if !ready || coll == nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			json.NewEncoder(w).Encode(map[string]string{"error": "Database chưa sẵn sàng"})
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
				json.NewEncoder(w).Encode(map[string]string{"error": "session_id không hợp lệ"})
				return
			}

			var targetSession LiveSession
			if errFind := coll.FindOne(ctx, bson.M{"_id": objID}).Decode(&targetSession); errFind != nil {
				w.WriteHeader(http.StatusNotFound)
				json.NewEncoder(w).Encode(map[string]string{"error": "Không tìm thấy phiên live"})
				return
			}

			if !canAdminManageStreamOrSession(ctx, claims, targetSession.StreamKey, targetSession.Streamer) {
				w.WriteHeader(http.StatusForbidden)
				json.NewEncoder(w).Encode(map[string]string{"error": "Quyền truy cập bị từ chối: Bạn không sở hữu bản ghi phiên live này"})
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
			_, errUp := coll.UpdateOne(ctx, bson.M{"_id": objID}, bson.M{"$set": updateFields})
			if errUp != nil {
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(map[string]string{"error": "Không thể cập nhật phiên live"})
				return
			}
			json.NewEncoder(w).Encode(map[string]string{
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
		newSession := LiveSession{
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
		_, errIns := coll.InsertOne(ctx, newSession)
		if errIns != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "Lỗi lưu video phát lại"})
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"message": "Đã thêm video xem lại thành công",
			"session": newSession,
		})

	case http.MethodDelete:
		sessionID := strings.TrimSpace(r.URL.Query().Get("id"))
		objID, errID := primitive.ObjectIDFromHex(sessionID)
		if errID != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "ID không hợp lệ"})
			return
		}

		if !ready || coll == nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			json.NewEncoder(w).Encode(map[string]string{"error": "Database chưa sẵn sàng"})
			return
		}

		var targetSession LiveSession
		if errFind := coll.FindOne(ctx, bson.M{"_id": objID}).Decode(&targetSession); errFind != nil {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"error": "Không tìm thấy phiên live"})
			return
		}

		if !canAdminManageStreamOrSession(ctx, claims, targetSession.StreamKey, targetSession.Streamer) {
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{"error": "Quyền truy cập bị từ chối: Bạn không có quyền xóa bản ghi của người khác"})
			return
		}

		_, _ = coll.UpdateOne(ctx, bson.M{"_id": objID}, bson.M{
			"$unset": bson.M{
				"replay_url":    "",
				"drive_file_id": "",
				"record_status": "",
			},
		})
		json.NewEncoder(w).Encode(map[string]string{"message": "Đã xóa video phát lại khỏi phiên này"})

	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}
