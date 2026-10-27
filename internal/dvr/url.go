package dvr

import (
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
)

var (
	// DriveFileIDRegex bắt file ID từ các dạng link Google Drive share
	DriveFileIDRegex = regexp.MustCompile(`(?:/d/|id=)([a-zA-Z0-9_-]{15,})`)
	// PureDriveIDRegex bắt chuỗi chỉ gồm Google Drive ID
	PureDriveIDRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]{20,}$`)
)

// NormalizeReplayURL chuẩn hóa link Google Drive (share link -> /preview embed link) hoặc giữ nguyên link .mp4 hợp lệ.
// Chặn triệt để các URI scheme nguy hiểm (javascript:, data:, vbscript:, file:...) để phòng chống Stored XSS.
func NormalizeReplayURL(raw string) (string, string) {
	clean := strings.TrimSpace(raw)
	if clean == "" {
		return "", ""
	}
	if matches := DriveFileIDRegex.FindStringSubmatch(clean); len(matches) >= 2 {
		fileID := matches[1]
		return fmt.Sprintf("https://drive.google.com/file/d/%s/preview", fileID), fileID
	}
	// Nếu chỉ truyền thẳng Google Drive File ID (chỉ gồm chữ, số, _, - và >= 20 ký tự)
	if PureDriveIDRegex.MatchString(clean) {
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

// SRSHTTPBaseURL trả về URL cơ sở cho dịch vụ phát bản ghi SRS HTTP
func SRSHTTPBaseURL() (string, error) {
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

// MakeSRSRecordURL ghép nối baseURL với đường dẫn file ghi hình
func MakeSRSRecordURL(baseURL, replayPath string) string {
	return strings.TrimRight(baseURL, "/") + "/" + strings.TrimLeft(replayPath, "/")
}

// DriveAutoUploadConfigured kiểm tra xem cấu hình tự động upload Google Drive đã được điền đủ chưa
func DriveAutoUploadConfigured() bool {
	return strings.TrimSpace(os.Getenv("GOOGLE_DRIVE_CLIENT_ID")) != "" &&
		strings.TrimSpace(os.Getenv("GOOGLE_DRIVE_CLIENT_SECRET")) != "" &&
		strings.TrimSpace(os.Getenv("GOOGLE_DRIVE_REFRESH_TOKEN")) != ""
}
