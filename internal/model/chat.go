package model

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// ChatMessage đại diện cho 1 tin nhắn trong phòng live
type ChatMessage struct {
	ID        primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	SessionID string             `bson:"session_id,omitempty" json:"session_id,omitempty"` // ID phiên live (để lưu trữ và xem lại)
	StreamKey string             `bson:"stream_key" json:"stream_key"`
	Username  string             `bson:"username" json:"username"`
	Avatar    string             `bson:"avatar,omitempty" json:"avatar,omitempty"`
	Role      string             `bson:"role" json:"role"` // "admin" | "streamer" | "user" | "guest"
	Message   string             `bson:"message" json:"message"`
	Type      string             `bson:"type" json:"type"` // "chat" | "system" | "reaction"
	CreatedAt time.Time          `bson:"created_at" json:"created_at"`
}

// WSInboundMessage payload gửi từ client lên server
type WSInboundMessage struct {
	Type      string `json:"type"`                 // "chat" | "reaction" | "auth_login" | "auth_token" | "auth_guest"
	Message   string `json:"message"`              // Nội dung tin nhắn
	Emoji     string `json:"emoji,omitempty"`      // Icon reaction (nếu type == "reaction")
	Username  string `json:"username,omitempty"`   // Tên đăng nhập (nếu type == "auth_login")
	Password  string `json:"password,omitempty"`   // Mật khẩu (nếu type == "auth_login")
	Token     string `json:"token,omitempty"`      // JWT Token xác thực socket
	Role      string `json:"role,omitempty"`       // Role gửi kèm (nếu có)
	Sender    string `json:"sender,omitempty"`     // Tên người gửi (nếu có)
	GuestName string `json:"guest_name,omitempty"` // Tên khách (nếu type == "auth_guest")
}

// WSOutboundMessage payload server broadcast tới các client
type WSOutboundMessage struct {
	Type          string                `json:"type"`                   // "chat" | "system" | "viewer_count" | "reaction" | "history" | "auth_login_result" | "error"
	Data          *ChatMessage          `json:"data,omitempty"`         // Tin nhắn đơn
	ViewerCount   int                   `json:"viewer_count,omitempty"` // Số người đang xem
	Emoji         string                `json:"emoji,omitempty"`        // Icon thả tim
	Sender        string                `json:"sender,omitempty"`       // Người gửi reaction
	History       []ChatMessage         `json:"history,omitempty"`      // Lịch sử tin nhắn gần đây
	Success       bool                  `json:"success,omitempty"`      // Cho auth_login_result
	Error         string                `json:"error,omitempty"`        // Cho auth_login_result hoặc error
	Token         string                `json:"token,omitempty"`        // Cho auth_login_result
	User          *User                 `json:"user,omitempty"`         // Cho auth_login_result
	StreamKey     string                `json:"stream_key,omitempty"`   // Cho auth_login_result
	PublishSecret string                `json:"publish_secret,omitempty"`
	StreamKeys    []StreamKeyCredential `json:"stream_keys,omitempty"` // Cho auth_login_result
}
