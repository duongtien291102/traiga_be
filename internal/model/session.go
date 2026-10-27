package model

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// LiveSession lưu trữ phiên live và đường dẫn video xem lại (Google Drive / SRS DVR)
type LiveSession struct {
	ID              primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	StreamKey       string             `bson:"stream_key" json:"stream_key"`
	Streamer        string             `bson:"streamer" json:"streamer"`
	Title           string             `bson:"title,omitempty" json:"title,omitempty"`
	App             string             `bson:"app" json:"app"`
	ClientIP        string             `bson:"client_ip" json:"client_ip"`
	Status          string             `bson:"status" json:"status"` // "live", "ended"
	StartedAt       time.Time          `bson:"started_at" json:"started_at"`
	EndedAt         *time.Time         `bson:"ended_at,omitempty" json:"ended_at,omitempty"`
	DurationSeconds int64              `bson:"duration_seconds" json:"duration_seconds"`
	ReplayURL       string             `bson:"replay_url,omitempty" json:"replay_url,omitempty"`
	DriveFileID     string              `bson:"drive_file_id,omitempty" json:"drive_file_id,omitempty"`
	RecordStatus    string              `bson:"record_status,omitempty" json:"record_status,omitempty"`
	PartIndex       int                 `bson:"part_index,omitempty" json:"part_index,omitempty"`
	ParentSessionID *primitive.ObjectID `bson:"parent_session_id,omitempty" json:"parent_session_id,omitempty"`
}

// AccessLog lưu vết lịch sử vào/ra, phiên live và các hoạt động quản trị
type AccessLog struct {
	ID        primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	Username  string             `bson:"username" json:"username"`
	Role      string             `bson:"role" json:"role"`     // "systemadmin", "admin", "user", "guest"
	Action    string             `bson:"action" json:"action"` // "login", "login_failed", "logout", "register", "create_user", "change_role", "delete_user", "start_stream", "stop_stream"
	IP        string             `bson:"ip" json:"ip"`
	Details   string             `bson:"details" json:"details"`
	CreatedAt time.Time          `bson:"created_at" json:"created_at"`
}
