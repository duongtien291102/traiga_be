package main

import (
	"context"
	"net/http"

	"livestream-be/internal/dvr"
	"livestream-be/internal/store"
)

var (
	driveFileIDRegex = dvr.DriveFileIDRegex
	pureDriveIDRegex = dvr.PureDriveIDRegex

	dvrHandlerInstance = dvr.NewHandler(
		func() *store.Store { return globalStore },
		func() []byte { return jwtSecret },
		verifySRSWebhookSecret,
	)
)

// normalizeReplayURL chuẩn hóa link Google Drive (share link -> /preview embed link) hoặc giữ nguyên link .mp4 hợp lệ.
func normalizeReplayURL(raw string) (string, string) {
	return dvr.NormalizeReplayURL(raw)
}

// getGoogleDriveAccessToken đổi Refresh Token lấy Access Token từ Google OAuth2
func getGoogleDriveAccessToken() (string, error) {
	return dvr.GetGoogleDriveAccessToken()
}

// uploadStreamToGoogleDrive tải luồng .mp4 từ SRS VPS và đẩy thẳng lên Google Drive qua Resumable Upload
func uploadStreamToGoogleDrive(displayName, vpsRecordURL string) (string, string, error) {
	return dvr.UploadStreamToGoogleDrive(displayName, vpsRecordURL)
}

func srsHTTPBaseURL() (string, error) {
	return dvr.SRSHTTPBaseURL()
}

func makeSRSRecordURL(baseURL, replayPath string) string {
	return dvr.MakeSRSRecordURL(baseURL, replayPath)
}

func driveAutoUploadConfigured() bool {
	return dvr.DriveAutoUploadConfigured()
}

// canAdminManageStreamOrSession kiểm tra quyền sở hữu StreamKey/Session để chống lỗ hổng IDOR giữa các Admin
func canAdminManageStreamOrSession(ctx context.Context, claims *JWTClaims, streamKey string, streamer string) bool {
	return dvrHandlerInstance.CanAdminManageStreamOrSession(ctx, claims, streamKey, streamer)
}

// dvrHandler nhận webhook on_dvr từ SRS khi file .mp4 ghi hình hoàn tất
func dvrHandler(w http.ResponseWriter, r *http.Request) {
	dvrHandlerInstance.DVR(w, r)
}

// archiveReplayHandler permanently stores a completed local DVR file in Drive.
func archiveReplayHandler(w http.ResponseWriter, r *http.Request) {
	dvrHandlerInstance.ArchiveReplay(w, r)
}

// apiReplaysHandler trả về danh sách các phiên live có video xem lại (Public cho toàn bộ người xem trên web)
func apiReplaysHandler(w http.ResponseWriter, r *http.Request) {
	dvrHandlerInstance.ListReplays(w, r)
}

// apiSessionReplayManageHandler cho phép Admin / SystemAdmin gắn link Google Drive hoặc xóa bản ghi xem lại
func apiSessionReplayManageHandler(w http.ResponseWriter, r *http.Request) {
	dvrHandlerInstance.ManageSessionReplay(w, r)
}
