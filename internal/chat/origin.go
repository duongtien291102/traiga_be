package chat

import (
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/gorilla/websocket"
)

// IsOriginAllowed kiểm tra xem Origin có nằm trong danh sách ALLOWED_ORIGINS hợp lệ hay không.
func IsOriginAllowed(origin string, requestHost string) bool {
	origin = strings.TrimSpace(origin)
	if origin == "" {
		return false
	}

	parsedOrigin, err := url.Parse(origin)
	if err != nil || parsedOrigin.Host == "" {
		return false
	}

	allowedStr := strings.TrimSpace(os.Getenv("ALLOWED_ORIGINS"))
	var allowedList []string
	if allowedStr != "" {
		allowedList = strings.Split(allowedStr, ",")
	} else {
		allowedList = []string{
			"http://localhost:3000",
			"http://127.0.0.1:3000",
			"http://localhost:5173",
			"http://127.0.0.1:5173",
			"http://localhost:8000",
			"http://127.0.0.1:8000",
			"https://localhost:3000",
			"https://127.0.0.1:3000",
			"https://traiga-fe.vercel.app",
		}
	}

	normOrigin := strings.ToLower(strings.TrimRight(origin, "/"))
	for _, item := range allowedList {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if item == "*" {
			if os.Getenv("ENV") == "production" || os.Getenv("NODE_ENV") == "production" {
				log.Println("⚠️ [ORIGIN] Ký tự đại diện '*' bị cấm trong production")
				continue
			}
			return true
		}
		if strings.ToLower(strings.TrimRight(item, "/")) == normOrigin {
			return true
		}
	}

	// Cho phép tất cả các preview domain của vercel.app
	hostLower := strings.ToLower(parsedOrigin.Host)
	if strings.HasSuffix(hostLower, ".vercel.app") || hostLower == "vercel.app" {
		return true
	}

	// Cho phép kết nối nếu cùng Host với backend hoặc reverse proxy
	if requestHost != "" && strings.EqualFold(parsedOrigin.Host, requestHost) {
		return true
	}

	return false
}

// CheckWebSocketOrigin kiểm tra Origin của request theo allowlist cấu hình.
func CheckWebSocketOrigin(r *http.Request) bool {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		if os.Getenv("ALLOW_EMPTY_ORIGIN") == "true" {
			return true
		}
		log.Printf("⛔ [WS REJECT] Thiếu Header Origin từ %s", r.RemoteAddr)
		return false
	}

	if !IsOriginAllowed(origin, r.Host) {
		log.Printf("⛔ [WS REJECT] Origin '%s' không nằm trong allowlist", origin)
		return false
	}
	return true
}

// DefaultUpgrader là cấu hình upgrader WebSocket mặc định.
var DefaultUpgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin:     CheckWebSocketOrigin,
}
