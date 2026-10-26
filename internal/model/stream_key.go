package model

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// StreamKey đại diện cho bảng stream_keys trong MongoDB
type StreamKey struct {
	ID                     primitive.ObjectID  `bson:"_id,omitempty" json:"id"`
	Key                    string              `bson:"key" json:"key"` // Public room identifier, not an ingest credential.
	PublishSecret          string              `bson:"-" json:"-"`
	PublishSecretEncrypted string              `bson:"publish_secret_enc,omitempty" json:"-"`
	PublishSecretHash      string              `bson:"publish_secret_hash,omitempty" json:"-"`
	Title                  string              `bson:"title" json:"title"`
	Streamer               string              `bson:"streamer" json:"streamer"`
	UserID                 *primitive.ObjectID `bson:"user_id,omitempty" json:"user_id,omitempty"`
	IsActive               bool                `bson:"is_active" json:"is_active"`
	MS                     string              `bson:"ms,omitempty" json:"ms,omitempty"`
	Chang                  string              `bson:"chang,omitempty" json:"chang,omitempty"`
	Loi                    string              `bson:"loi,omitempty" json:"loi,omitempty"`
	CanVay                 string              `bson:"can_vay,omitempty" json:"can_vay,omitempty"`
	DatNuoc                string              `bson:"dat_nuoc,omitempty" json:"dat_nuoc,omitempty"`
	Thumb                  string              `bson:"thumb,omitempty" json:"thumb,omitempty"`
	CreatedAt              time.Time           `bson:"created_at" json:"created_at"`
}

type StreamKeyCredential struct {
	StreamKey
	PublishSecret string `json:"publish_secret"`
}
