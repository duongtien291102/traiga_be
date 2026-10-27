package main

import (
	"net/http"

	"livestream-be/internal/chat"
	"livestream-be/internal/model"
	"livestream-be/internal/store"
)

// Type aliases for gradual refactoring (Phase 2 & 4)
type (
	ChatMessage       = model.ChatMessage
	WSInboundMessage  = model.WSInboundMessage
	WSOutboundMessage = model.WSOutboundMessage
	ChatHub           = chat.Hub
	ChatClient        = chat.Client
	broadcastEvent    = chat.BroadcastEvent
)

var globalChatHub = chat.NewHub()

func init() {
	go globalChatHub.Run()
}

var chatService = chat.NewService(
	func() *store.Store { return globalStore },
	func() []byte { return jwtSecret },
	createToken,
	hydratePublishSecret,
	recordAccessLog,
)

var chatHandler = chat.NewHandler(
	globalChatHub,
	chatService,
	getClientIP,
)

// isOriginAllowed kiểm tra xem Origin có nằm trong danh sách ALLOWED_ORIGINS hợp lệ hay không.
func isOriginAllowed(origin string, requestHost string) bool {
	return chat.IsOriginAllowed(origin, requestHost)
}

// checkWebSocketOrigin kiểm tra Origin của request theo allowlist cấu hình.
func checkWebSocketOrigin(r *http.Request) bool {
	return chat.CheckWebSocketOrigin(r)
}


// maskPhoneNumbers che bốn chữ số cuối của số điện thoại Việt Nam trong chat.
func maskPhoneNumbers(message string) string {
	return chat.MaskPhoneNumbers(message)
}

// sanitizeChatHistory lọc số điện thoại trong lịch sử chat.
func sanitizeChatHistory(messages []ChatMessage, canViewPhones bool) []ChatMessage {
	return chat.SanitizeChatHistory(messages, canViewPhones)
}

// saveChatMessage lưu tin nhắn vào MongoDB collection chat_messages.
func saveChatMessage(msg ChatMessage) {
	chatService.SaveChatMessage(msg)
}

// broadcastResetChat gửi sự kiện reset/xóa trắng khung chat tới tất cả người xem trong phòng.
func broadcastResetChat(streamKey string) {
	globalChatHub.BroadcastResetChat(streamKey)
}

// resetRoomChat phát lệnh reset khung chat trên giao diện người xem.
func resetRoomChat(streamKey string) {
	broadcastResetChat(streamKey)
}

// clearRoomChatHistory giữ tên hàm tương thích với các điểm gọi cũ.
func clearRoomChatHistory(streamKey string) {
	broadcastResetChat(streamKey)
}

// getRecentChatHistory lấy các tin nhắn của phiên live hiện tại.
func getRecentChatHistory(streamKey string) []ChatMessage {
	return chatService.GetRecentChatHistory(streamKey)
}

// wsChatHandler xử lý nâng cấp WebSocket cho phòng chat.
func wsChatHandler(w http.ResponseWriter, r *http.Request) {
	chatHandler.HandleWS(w, r)
}

// apiChatHistoryHandler REST API lấy lịch sử chat.
func apiChatHistoryHandler(w http.ResponseWriter, r *http.Request) {
	chatHandler.HandleHistory(w, r)
}
