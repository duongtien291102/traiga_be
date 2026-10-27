package chat

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/options"

	"livestream-be/internal/model"
	"livestream-be/internal/security/token"
	"livestream-be/internal/store"
)

// Service cung cấp các thao tác dữ liệu MongoDB và phân quyền liên quan đến Chat.
type Service struct {
	GetStore             func() *store.Store
	GetJwtSecret         func() []byte
	CreateToken          func(user model.User) (string, error)
	HydratePublishSecret func(key *model.StreamKey) error
	RecordAccessLog      func(username, role, action, ip, details string)
}

// NewService tạo mới Chat Service.
func NewService(
	getStore func() *store.Store,
	getJwtSecret func() []byte,
	createToken func(user model.User) (string, error),
	hydratePublishSecret func(key *model.StreamKey) error,
	recordAccessLog func(username, role, action, ip, details string),
) *Service {
	return &Service{
		GetStore:             getStore,
		GetJwtSecret:         getJwtSecret,
		CreateToken:          createToken,
		HydratePublishSecret: hydratePublishSecret,
		RecordAccessLog:      recordAccessLog,
	}
}

// SaveChatMessage lưu tin nhắn vào MongoDB collection chat_messages.
func (s *Service) SaveChatMessage(msg model.ChatMessage) {
	var st *store.Store
	if s.GetStore != nil {
		st = s.GetStore()
	}
	if st == nil || st.Chat == nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if msg.SessionID == "" && st.Sessions != nil && msg.StreamKey != "" {
		var activeSess model.LiveSession
		optsSess := options.FindOne().SetSort(bson.M{"started_at": -1})
		if err := st.Sessions.FindOne(ctx, bson.M{"stream_key": msg.StreamKey, "status": "live"}, optsSess).Decode(&activeSess); err == nil {
			msg.SessionID = activeSess.ID.Hex()
		}
	}

	_, err := st.Chat.InsertOne(ctx, msg)
	if err != nil {
		log.Printf("⚠️ Không thể lưu tin nhắn chat vào MongoDB: %v", err)
	}
}

// GetRecentChatHistory lấy các tin nhắn của phiên live hiện tại.
func (s *Service) GetRecentChatHistory(streamKey string) []model.ChatMessage {
	var st *store.Store
	if s.GetStore != nil {
		st = s.GetStore()
	}
	if st == nil || st.Chat == nil {
		return []model.ChatMessage{}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if st.Sessions != nil {
		var activeSession model.LiveSession
		optsSess := options.FindOne().SetSort(bson.M{"started_at": -1})
		err := st.Sessions.FindOne(ctx, bson.M{"stream_key": streamKey, "status": "live"}, optsSess).Decode(&activeSession)
		if err != nil {
			return []model.ChatMessage{}
		}

		opts := options.Find().SetSort(bson.M{"created_at": -1}).SetLimit(50)
		filter := bson.M{
			"stream_key": streamKey,
			"created_at": bson.M{"$gte": activeSession.StartedAt},
		}
		cursor, err := st.Chat.Find(ctx, filter, opts)
		if err != nil {
			return []model.ChatMessage{}
		}
		defer cursor.Close(ctx)

		msgs := make([]model.ChatMessage, 0)
		_ = cursor.All(ctx, &msgs)

		for i, j := 0, len(msgs)-1; i < j; i, j = i+1, j-1 {
			msgs[i], msgs[j] = msgs[j], msgs[i]
		}
		for i := range msgs {
			if msgs[i].Username == "sysadmin" || msgs[i].Role == "systemadmin" {
				msgs[i].Username = "Ban Quản Trị"
			} else if msgs[i].Username == "admin01" {
				msgs[i].Username = "Chủ Trại"
			}
		}

		return msgs
	}

	return []model.ChatMessage{}
}

// IsRoomOwnerUserID kiểm tra quyền sở hữu phòng từ bản ghi MongoDB.
func (s *Service) IsRoomOwnerUserID(streamKey, userID string) bool {
	var st *store.Store
	if s.GetStore != nil {
		st = s.GetStore()
	}
	if st == nil || st.Keys == nil || st.Users == nil || strings.TrimSpace(userID) == "" {
		return false
	}
	userObjectID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	var room model.StreamKey
	if err := st.Keys.FindOne(ctx, bson.M{"key": streamKey}).Decode(&room); err != nil {
		return false
	}
	if room.UserID != nil {
		return *room.UserID == userObjectID
	}
	if strings.TrimSpace(room.Streamer) == "" {
		return false
	}
	var owner model.User
	ownerName := strings.TrimSpace(room.Streamer)
	err = st.Users.FindOne(ctx, bson.M{"$or": []bson.M{
		{"username": strings.ToLower(ownerName)},
		{"full_name": ownerName},
	}}).Decode(&owner)
	return err == nil && owner.ID == userObjectID
}

// RequestCanViewRoomPhones xác thực token xem người gọi có quyền xem số điện thoại phòng live không.
func (s *Service) RequestCanViewRoomPhones(r *http.Request, streamKey string) bool {
	revocationStore := token.Global()
	if revocationStore == nil {
		return false
	}
	tokenString := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	if tokenString == "" || len(tokenString) > 4096 || revocationStore.IsTokenRevoked(tokenString) {
		return false
	}

	var secret []byte
	if s.GetJwtSecret != nil {
		secret = s.GetJwtSecret()
	}

	t, err := jwt.ParseWithClaims(tokenString, &model.JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return secret, nil
	})
	if err != nil || !t.Valid {
		return false
	}
	claims, ok := t.Claims.(*model.JWTClaims)
	return ok && s.IsRoomOwnerUserID(streamKey, claims.UserID)
}
