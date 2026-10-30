package dvr

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
	"strings"
	"time"
)

// GetGoogleDriveAccessToken đổi Refresh Token lấy Access Token từ Google OAuth2
func GetGoogleDriveAccessToken() (string, error) {
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

// UploadStreamToGoogleDrive tải luồng .mp4 từ SRS VPS và đẩy thẳng lên Google Drive qua Resumable Upload
func UploadStreamToGoogleDrive(displayName, vpsRecordURL string) (string, string, error) {
	accessToken, err := GetGoogleDriveAccessToken()
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

// WaitForDVRNormalization chờ file đánh dấu .avsync-v1 xuất hiện trên SRS VPS (tối đa timeout)
// để đảm bảo worker FFmpeg đã chuẩn hóa đồng bộ âm thanh - hình ảnh xong trước khi tải.
func WaitForDVRNormalization(ctx context.Context, vpsRecordURL string, timeout time.Duration) {
	if vpsRecordURL == "" {
		return
	}
	markerURL := vpsRecordURL + ".avsync-v1"
	client := &http.Client{Timeout: 3 * time.Second}
	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, markerURL, nil)
		if err == nil {
			resp, errResp := client.Do(req)
			if errResp == nil {
				_ = resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					log.Printf("🎬 [SRS DVR] Bản ghi đã được chuẩn hóa đồng bộ A/V (.avsync-v1) sẵn sàng tải: %s", vpsRecordURL)
					return
				}
			}
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if time.Now().After(deadline) {
				log.Printf("⚠️ [SRS DVR] Quá thời gian chờ .avsync-v1, tiếp tục xử lý bản ghi: %s", vpsRecordURL)
				return
			}
		}
	}
}
