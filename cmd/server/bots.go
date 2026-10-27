package main

import (
	"context"
	"encoding/json"
	"net/http"

	"go.mongodb.org/mongo-driver/mongo"

	"livestream-be/internal/bot"
	"livestream-be/internal/model"
	"livestream-be/internal/store"
)

// Type aliases for gradual refactoring (Phase 2 & 4)
type (
	ChatBot           = model.ChatBot
	RoomBotAssignment = model.RoomBotAssignment
	BotRunnerManager  = bot.RunnerManager
)

var (
	botsColl     *mongo.Collection
	roomBotsColl *mongo.Collection
)

var globalBotManager = bot.NewRunnerManager(
	func(streamKey string, msg *model.ChatMessage) {
		go saveChatMessage(*msg)

		out := WSOutboundMessage{
			Type: "chat",
			Data: msg,
		}
		if ownerBytes, err := json.Marshal(out); err == nil {
			maskedMsg := *msg
			maskedMsg.Message = maskPhoneNumbers(maskedMsg.Message)
			maskedOut := WSOutboundMessage{Type: "chat", Data: &maskedMsg}
			if publicBytes, marshalErr := json.Marshal(maskedOut); marshalErr == nil {
				if globalChatHub != nil {
					globalChatHub.BroadcastMessage(streamKey, publicBytes, ownerBytes)
				}
			}
		}
	},
	func(streamKey, emoji, sender string) {
		out := WSOutboundMessage{
			Type:   "reaction",
			Emoji:  emoji,
			Sender: sender,
		}
		if b, err := json.Marshal(out); err == nil {
			if globalChatHub != nil {
				globalChatHub.BroadcastMessage(streamKey, b, nil)
			}
		}
	},
)

var botHandler = bot.NewHandler(
	func() *store.Store { return globalStore },
	getUserFromAuthHeader,
	func(ctx context.Context, claims *model.JWTClaims, streamKey string) bool {
		return canAdminManageStreamOrSession(ctx, claims, streamKey, "")
	},
	recordAccessLog,
	globalBotManager,
)

// cleanMockBots xóa bỏ các Bot mẫu mock data để dữ liệu Bot trong DB chỉ bao gồm các Bot do Admin cấu hình thật
func cleanMockBots() {
	botHandler.CleanMockBots()
}

// seedDefaultBots giữ lại tương thích, tự động dọn dẹp mock data
func seedDefaultBots() {
	cleanMockBots()
}

// sysadminBotsHandler quản lý CRUD Bot dành riêng cho SystemAdmin
// GET /api/sysadmin/bots - Lấy danh sách bot
// POST /api/sysadmin/bots - Tạo bot mới
// PUT /api/sysadmin/bots - Cập nhật bot
// DELETE /api/sysadmin/bots?id=xxx - Xóa bot
func sysadminBotsHandler(w http.ResponseWriter, r *http.Request) {
	botHandler.SysadminBots(w, r)
}

// adminAvailableBotsHandler trả về danh sách bot đang hoạt động để Admin chọn
// GET /api/admin/bots
func adminAvailableBotsHandler(w http.ResponseWriter, r *http.Request) {
	botHandler.AdminAvailableBots(w, r)
}

// adminRoomBotsHandler cho phép Admin xem hoặc chọn tối đa 5 bot và bật/tắt vào phòng live
// GET /api/admin/room-bots?streamKey=xxx
// POST /api/admin/room-bots
func adminRoomBotsHandler(w http.ResponseWriter, r *http.Request) {
	botHandler.AdminRoomBots(w, r)
}
