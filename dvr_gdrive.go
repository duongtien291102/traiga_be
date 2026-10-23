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

// normalizeReplayURL chuẩn hóa link Google Drive (share link -> /preview embed link) hoặc giữ nguyên link .mp4
func normalizeReplayURL(raw string) (string, string) {
	clean := strings.TrimSpace(raw)
	if clean == "" {
		return "", ""
	}
	if matches := driveFileIDRegex.FindStringSubmatch(clean); len(matches) >= 2 {
		fileID := matches[1]
		return fmt.Sprintf("https://drive.google.com/file/d/%s/preview", fileID), fileID
	}
	// Nếu chỉ truyền thẳng Google Drive File ID (không chứa dấu / hay :)
	if !strings.Contains(clean, "/") && !strings.Contains(clean, ":") && len(clean) >= 20 {
		return fmt.Sprintf("https://drive.google.com/file/d/%s/preview", clean), clean
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
			permResp.Body.Close()
		}
	}

	previewURL := fmt.Sprintf("https://drive.google.com/file/d/%s/preview", uploadedFile.ID)
	return uploadedFile.ID, previewURL, nil
}

// dvrHandler nhận webhook on_dvr từ SRS khi file .mp4 ghi hình hoàn tất
func dvrHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var payload SRSAuthPayload
	body, err := io.ReadAll(r.Body)
	if err == nil && len(body) > 0 {
		_ = json.Unmarshal(body, &payload)
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

	relativeReplayPath := fmt.Sprintf("/record/%s/%s", appName, baseName)
	srsBaseURL := strings.TrimRight(strings.TrimSpace(os.Getenv("SRS_HTTP_URL")), "/")
	if srsBaseURL == "" {
		srsBaseURL = "http://103.82.26.60:8080"
	}
	vpsRecordURL := srsBaseURL + relativeReplayPath

	log.Printf("🎬 [SRS DVR RECORDED] Phiên live '%s' đã xuất file: %s", streamKey, relativeReplayPath)

	mongoMutex.RLock()
	ready := isMongoReady
	coll := sessionsColl
	kColl := keysColl
	mongoMutex.RUnlock()

	if ready && coll != nil && streamKey != "" && baseName != "" {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

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

			// Tìm phiên live gần nhất của stream_key này
			var targetSession LiveSession
			opts := options.FindOne().SetSort(bson.M{"started_at": -1})
			errFind := coll.FindOne(ctx, bson.M{"stream_key": streamKey}, opts).Decode(&targetSession)

			now := time.Now()
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
				_, _ = coll.InsertOne(ctx, targetSession)
			} else {
				updateFields := bson.M{
					"replay_url":    relativeReplayPath,
					"record_status": "ready",
				}
				if targetSession.Title == "" {
					updateFields["title"] = roomTitle
				}
				_, _ = coll.UpdateOne(ctx, bson.M{"_id": targetSession.ID}, bson.M{"$set": updateFields})
			}

			// Nếu đã cấu hình Google Drive OAuth2 -> Tự động đẩy file .mp4 lên Google Drive
			if os.Getenv("GOOGLE_DRIVE_REFRESH_TOKEN") != "" {
				driveFileName := fmt.Sprintf("TraiGa_%s_%s.mp4", streamKey, now.Format("20060102_150405"))
				log.Printf("☁️ [GOOGLE DRIVE UPLOAD] Đang tải '%s' lên Google Drive...", driveFileName)

				fileID, previewURL, errUp := uploadStreamToGoogleDrive(driveFileName, vpsRecordURL)
				if errUp != nil {
					log.Printf("⚠️ [GOOGLE DRIVE UPLOAD ERROR] Không thể tải '%s' lên Google Drive: %v", driveFileName, errUp)
					return
				}

				ctxUp, cancelUp := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancelUp()
				_, _ = coll.UpdateOne(ctxUp, bson.M{"_id": targetSession.ID}, bson.M{
					"$set": bson.M{
						"drive_file_id": fileID,
						"replay_url":    previewURL,
						"record_status": "uploaded_drive",
					},
				})
				log.Printf("✅ [GOOGLE DRIVE UPLOAD SUCCESS] Đã lưu lên Google Drive: %s", previewURL)
			}
		}()
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `{"code":0}`)
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

	mongoMutex.RLock()
	ready := isMongoReady
	coll := sessionsColl
	mongoMutex.RUnlock()

	if !ready || coll == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]string{"error": "Database chưa sẵn sàng"})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	switch r.Method {
	case http.MethodPost, http.MethodPut:
		var req struct {
			SessionID string `json:"session_id"`
			StreamKey string `json:"stream_key"`
			Title     string `json:"title"`
			ReplayURL string `json:"replay_url"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "Dữ liệu không hợp lệ"})
			return
		}

		normalizedURL, driveID := normalizeReplayURL(req.ReplayURL)
		if normalizedURL == "" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "Vui lòng nhập đường dẫn Google Drive hoặc link video hợp lệ"})
			return
		}

		recordStatus := "ready"
		if driveID != "" || strings.Contains(normalizedURL, "drive.google.com") {
			recordStatus = "uploaded_drive"
		}

		// Nếu có truyền session_id -> Cập nhật vào session đó
		if strings.TrimSpace(req.SessionID) != "" {
			objID, errID := primitive.ObjectIDFromHex(strings.TrimSpace(req.SessionID))
			if errID != nil {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{"error": "session_id không hợp lệ"})
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
		streamKey := strings.TrimSpace(req.StreamKey)
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
