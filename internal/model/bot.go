package model

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// ChatBot đại diện cho 1 Bot tương tác được tạo bởi SystemAdmin
type ChatBot struct {
	ID        primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	Name      string             `bson:"name" json:"name"`             // Tên hiển thị của Bot
	Avatar    string             `bson:"avatar" json:"avatar"`         // Icon / Emoji đại diện
	Role      string             `bson:"role" json:"role"`             // "user" | "vip" | "streamer"
	Messages  []string           `bson:"messages" json:"messages"`     // Danh sách câu thoại đặt sẵn
	Interval  int                `bson:"interval" json:"interval"`     // Tần suất chat (giây, mặc định 15)
	IsActive  bool               `bson:"is_active" json:"is_active"`   // Cho phép sử dụng hay không
	CreatedBy string             `bson:"created_by" json:"created_by"` // Username SystemAdmin tạo
	CreatedAt time.Time          `bson:"created_at" json:"created_at"`
	UpdatedAt time.Time          `bson:"updated_at" json:"updated_at"`
}

// RoomBotAssignment lưu cấu hình bot mà Admin chọn cho phòng live của mình (tối đa 5 bot)
type RoomBotAssignment struct {
	ID        primitive.ObjectID   `bson:"_id,omitempty" json:"id"`
	StreamKey string               `bson:"stream_key" json:"stream_key"` // Khóa luồng live
	AdminUser string               `bson:"admin_user" json:"admin_user"` // Username của Admin
	BotIDs    []primitive.ObjectID `bson:"bot_ids" json:"bot_ids"`       // Danh sách tối đa 5 bot ID
	IsRunning bool                 `bson:"is_running" json:"is_running"` // Trạng thái đang chạy
	UpdatedAt time.Time            `bson:"updated_at" json:"updated_at"`
}
