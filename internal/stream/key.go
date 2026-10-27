package stream

import (
	"crypto/rand"
	"encoding/hex"
	"strings"

	"livestream-be/internal/model"
)

// MaskIP che giấu địa chỉ IP của streamer để bảo vệ quyền riêng tư
func MaskIP(ip string) string {
	if ip == "" {
		return "***"
	}
	parts := strings.Split(ip, ":")
	host := parts[0]
	dotParts := strings.Split(host, ".")
	if len(dotParts) == 4 {
		return dotParts[0] + "." + dotParts[1] + "." + dotParts[2] + ".***"
	}
	return "***"
}

// GenerateStreamKey sinh khóa luồng có độ ngẫu nhiên cao (entropy) cho RTMP.
func GenerateStreamKey() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// StreamKeyCredentials tạo danh sách thông tin chứng thực StreamKeyCredential
func StreamKeyCredentials(keys []model.StreamKey) []model.StreamKeyCredential {
	credentials := make([]model.StreamKeyCredential, 0, len(keys))
	for _, key := range keys {
		credentials = append(credentials, model.StreamKeyCredential{
			StreamKey:     key,
			PublishSecret: key.PublishSecret,
		})
	}
	return credentials
}
