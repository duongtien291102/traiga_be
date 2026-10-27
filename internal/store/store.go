package store

import (
	"context"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// Store giữ toàn bộ kết nối MongoDB và các collection handles.
// Sau khi New() hoàn tất, Store là immutable — không có mutation sau init.
type Store struct {
	Client *mongo.Client
	DB     *mongo.Database

	Users      *mongo.Collection // "users"
	Keys       *mongo.Collection // "stream_keys"
	Sessions   *mongo.Collection // "live_sessions"
	Chat       *mongo.Collection // "chat_messages"
	Chickens   *mongo.Collection // "chickens"
	AccessLogs *mongo.Collection // "access_logs"
	Bots       *mongo.Collection // "chat_bots"
	RoomBots   *mongo.Collection // "room_bot_assignments"

	Ready bool
}

// New kết nối tới MongoDB, gán các collection, và trả về *Store.
// Không lock, không log.Fatalf — caller chịu trách nhiệm xử lý lỗi.
func New(uri, dbName string) (*Store, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	clientOptions := options.Client().ApplyURI(uri)
	client, err := mongo.Connect(ctx, clientOptions)
	if err != nil {
		return nil, fmt.Errorf("mongo.Connect: %w", err)
	}

	if err := client.Ping(ctx, nil); err != nil {
		_ = client.Disconnect(ctx) // tránh leak connection pool khi Ping fail
		return nil, fmt.Errorf("mongo.Ping: %w", err)
	}

	db := client.Database(dbName)
	s := &Store{
		Client:     client,
		DB:         db,
		Users:      db.Collection("users"),
		Keys:       db.Collection("stream_keys"),
		Sessions:   db.Collection("live_sessions"),
		Chat:       db.Collection("chat_messages"),
		Chickens:   db.Collection("chickens"),
		AccessLogs: db.Collection("access_logs"),
		Bots:       db.Collection("chat_bots"),
		RoomBots:   db.Collection("room_bot_assignments"),
		Ready:      true,
	}
	return s, nil
}

// Ping kiểm tra kết nối MongoDB còn sống không.
func (s *Store) Ping(ctx context.Context) error {
	if s == nil || s.Client == nil {
		return fmt.Errorf("store not initialized")
	}
	return s.Client.Ping(ctx, nil)
}

// IsReady trả về true nếu Store đã được khởi tạo thành công.
func (s *Store) IsReady() bool {
	return s != nil && s.Ready
}

// CreateIndexes tạo tất cả index cần thiết cho các collection.
// Tách từ initMongoDB — để dễ test và tái sử dụng.
// Pattern _, _ = giữ nguyên từ code gốc: idempotent, index đã tồn tại không critical.
func (s *Store) CreateIndexes(ctx context.Context) {
	// users: unique username
	_, _ = s.Users.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.M{"username": 1},
		Options: options.Index().SetUnique(true),
	})
	// stream_keys: unique key
	_, _ = s.Keys.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.M{"key": 1},
		Options: options.Index().SetUnique(true),
	})
	// chickens: sort by created_at DESC
	_, _ = s.Chickens.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys: bson.D{{Key: "created_at", Value: -1}},
	})
	// chickens: filter by status
	_, _ = s.Chickens.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys: bson.D{{Key: "status", Value: 1}},
	})
	// chat_messages: compound index stream_key + created_at DESC
	_, _ = s.Chat.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys: bson.D{{Key: "stream_key", Value: 1}, {Key: "created_at", Value: -1}},
	})
	// access_logs: sort by created_at DESC
	_, _ = s.AccessLogs.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys: bson.D{{Key: "created_at", Value: -1}},
	})
	// live_sessions: sort by started_at DESC
	_, _ = s.Sessions.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys: bson.D{{Key: "started_at", Value: -1}},
	})
}

// SetKeysForTest cho phép test thay thế collection Keys bằng mock.
// CHỈ dùng trong test — không dùng trong production code.
//
// WARNING: Hàm này MUTATE s.Keys — nếu test chạy song song (t.Parallel()),
// sẽ có race condition. Test hiện tại (p05) chạy tuần tự nên an toàn.
// Nếu future thêm parallel test → phải dùng lock hoặc tách Store per test.
func (s *Store) SetKeysForTest(coll *mongo.Collection) {
	s.Keys = coll
}
