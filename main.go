package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"

	"livestream-be/internal/auth"
	"livestream-be/internal/model"
	"livestream-be/internal/security/limiter"
	"livestream-be/internal/security/token"
	"livestream-be/internal/store"
)

// Type aliases for gradual refactoring (Phase 2)
type (
	User                = model.User
	StreamKey           = model.StreamKey
	StreamKeyCredential = model.StreamKeyCredential
	LiveSession         = model.LiveSession
	AccessLog           = model.AccessLog
	SRSAuthPayload      = model.SRSAuthPayload
	JWTClaims           = model.JWTClaims
)

// Backwards-compatibility layer for root package files during gradual refactoring (Phases 1-4)
var globalTokenRevocationStore = token.Global()

const (
	SmallJSONMaxBodyBytes = limiter.SmallJSONMaxBodyBytes
	DefaultMaxBodyBytes   = limiter.DefaultMaxBodyBytes
)

func getClientIP(r *http.Request) string {
	return limiter.GetClientIP(r)
}

func limitRequestBody(w http.ResponseWriter, r *http.Request, maxBytes int64) {
	limiter.LimitRequestBody(w, r, maxBytes)
}

type TokenBucket = limiter.TokenBucket

var (
	NewTokenBucket           = limiter.NewTokenBucket
	RateLimitLoginMiddleware = limiter.RateLimitLoginMiddleware
)

func streamKeyCredentials(keys []StreamKey) []StreamKeyCredential {
	credentials := make([]StreamKeyCredential, 0, len(keys))
	for _, key := range keys {
		credentials = append(credentials, StreamKeyCredential{StreamKey: key, PublishSecret: key.PublishSecret})
	}
	return credentials
}

var (
	globalStore    *store.Store
	mongoClient    *mongo.Client
	db             *mongo.Database
	usersColl      *mongo.Collection
	keysColl       *mongo.Collection
	sessionsColl   *mongo.Collection
	chatColl       *mongo.Collection
	chickensColl   *mongo.Collection
	accessLogsColl *mongo.Collection
	mongoMutex     sync.RWMutex
	isMongoReady   bool
	jwtSecret      []byte
)

var userAuthHandler = auth.NewHandler(
	func() *store.Store { return globalStore },
	func() []byte { return jwtSecret },
	recordAccessLog,
	ensureAdminStreamKeys,
	generateStreamKey,
	insertStreamKey,
)


// maskIP che giấu địa chỉ IP của streamer để bảo vệ quyền riêng tư
func maskIP(ip string) string {
	if ip == "" {
		return "***"
	}
	parts := strings.Split(ip, ":")
	host := parts[0]
	dotParts := strings.Split(host, ".")
	if len(dotParts) == 4 {
		return fmt.Sprintf("%s.%s.%s.***", dotParts[0], dotParts[1], dotParts[2])
	}
	return "***"
}

// generateSecureRandomPassword tạo mật khẩu an toàn ngẫu nhiên độ dài chỉ định
func generateSecureRandomPassword(length int) string {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("AdminSec@%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// generateStreamKey returns a high-entropy key suitable for RTMP publishing.
func generateStreamKey() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// ensureAdminStreamKeys migrates username-based legacy keys and creates a key
// for admins that do not have one yet.
func ensureAdminStreamKeys(ctx context.Context, user User) ([]StreamKey, error) {
	if keysColl == nil {
		return nil, fmt.Errorf("stream key database is unavailable")
	}
	filter := bson.M{"$or": []bson.M{{"user_id": user.ID}, {"streamer": user.FullName}, {"streamer": user.Username}}}
	cursor, err := keysColl.Find(ctx, filter)
	if err != nil {
		return nil, err
	}
	keys := make([]StreamKey, 0)
	if err := cursor.All(ctx, &keys); err != nil {
		_ = cursor.Close(ctx)
		return nil, err
	}
	_ = cursor.Close(ctx)

	for i := range keys {
		if keys[i].PublishSecret == "" {
			if err := hydratePublishSecret(&keys[i]); err != nil {
				return nil, fmt.Errorf("không thể mở khóa phát của phòng %s: %w", keys[i].ID.Hex(), err)
			}
		}
		if strings.EqualFold(keys[i].Key, user.Username) {
			newKey, err := generateStreamKey()
			if err != nil {
				return nil, err
			}
			storedKey, err := streamKeyForStorage(keys[i])
			if err != nil {
				return nil, err
			}
			if _, err := keysColl.UpdateOne(ctx, bson.M{"_id": keys[i].ID}, bson.M{"$set": bson.M{
				"key":                 newKey,
				"publish_secret_enc":  storedKey.PublishSecretEncrypted,
				"publish_secret_hash": storedKey.PublishSecretHash,
			}}); err != nil {
				return nil, err
			}
			keys[i].Key = newKey
		}
	}

	if len(keys) == 0 {
		newKey, err := generateStreamKey()
		if err != nil {
			return nil, err
		}
		key := StreamKey{Key: newKey, Title: fmt.Sprintf("Kênh %s", user.FullName), Streamer: user.FullName, UserID: &user.ID, IsActive: true, CreatedAt: time.Now()}
		storedKey, err := streamKeyForStorage(key)
		if err != nil {
			return nil, err
		}
		result, err := keysColl.InsertOne(ctx, storedKey)
		if err != nil {
			return nil, err
		}
		key = storedKey
		key.ID = result.InsertedID.(primitive.ObjectID)
		keys = append(keys, key)
	}
	return keys, nil
}

// initJWTSecret kiểm tra và nạp JWT_SECRET bắt buộc từ môi trường
func initJWTSecret() {
	_ = godotenv.Load()
	secret := strings.TrimSpace(os.Getenv("JWT_SECRET"))
	if len(secret) < 32 {
		log.Fatalf("❌ FATAL SECURITY ERROR: Biến môi trường JWT_SECRET bắt buộc phải có độ dài tối thiểu 32 ký tự! Server dừng khởi động an toàn.")
	}
	jwtSecret = []byte(secret)
}

// initMongoDB kết nối tới MongoDB Atlas và khởi tạo collections
func initMongoDB() {
	_ = godotenv.Load()
	initJWTSecret()
	if err := initStreamKeyCrypto(); err != nil {
		log.Fatalf("❌ FATAL SECURITY ERROR: %v", err)
	}
	if strings.TrimSpace(os.Getenv("STREAM_KEY_ENCRYPTION_KEY")) == "" {
		log.Println("⚠️ STREAM_KEY_ENCRYPTION_KEY chưa được đặt; publish secret đang dùng khóa dẫn xuất từ JWT_SECRET. Hãy cấu hình khóa riêng và giữ ổn định qua các lần triển khai.")
	}

	uri := os.Getenv("MONGO_URI")
	dbName := os.Getenv("MONGO_DB")
	if dbName == "" {
		dbName = "livestream_db"
	}

	if uri == "" {
		log.Println("⚠️ Không tìm thấy biến MONGO_URI trong .env! Chạy chế độ bộ nhớ đệm.")
		return
	}

	st, err := store.New(uri, dbName)
	if err != nil {
		log.Printf("❌ Kết nối MongoDB thất bại: %v", err)
		return
	}

	mongoMutex.Lock()
	globalStore = st
	mongoClient = st.Client
	db = st.DB
	usersColl = st.Users
	keysColl = st.Keys
	sessionsColl = st.Sessions
	chatColl = st.Chat
	chickensColl = st.Chickens
	accessLogsColl = st.AccessLogs
	botsColl = st.Bots
	roomBotsColl = st.RoomBots
	isMongoReady = st.Ready
	mongoMutex.Unlock()

	log.Printf("✅ Đã kết nối thành công tới MongoDB Atlas (Database: %s)", dbName)

	// Dọn dẹp bot mẫu mock data (nếu có)
	go cleanMockBots()

	// Tạo index cho các collection
	st.CreateIndexes(context.Background())

	// Khởi tạo tài khoản System Admin & Admin mặc định và key mẫu
	seedDefaultData()
	secretCtx, secretCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer secretCancel()
	if err := migratePublishSecrets(secretCtx); err != nil {
		log.Fatalf("❌ Không thể khởi tạo mã bảo vệ khóa phát: %v", err)
	}
}

// recordAccessLog lưu vết sự kiện đăng nhập, đăng xuất, phiên live và hoạt động quản trị
func recordAccessLog(username, role, action, ip, details string) {
	mongoMutex.RLock()
	ready := isMongoReady
	coll := accessLogsColl
	mongoMutex.RUnlock()

	if !ready || coll == nil {
		return
	}

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if username == "" {
			username = "Ẩn danh"
		}
		if role == "" {
			role = "guest"
		}

		logEntry := AccessLog{
			Username:  username,
			Role:      role,
			Action:    action,
			IP:        ip,
			Details:   details,
			CreatedAt: time.Now(),
		}
		_, _ = coll.InsertOne(ctx, logEntry)
	}()
}

// seedDefaultData khởi tạo tài khoản quản trị an toàn (không dùng mật khẩu mặc định, không log mật khẩu)
func seedDefaultData() {
	if !isMongoReady {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 1. Khởi tạo tài khoản Tổng Quản Trị Hệ Thống (sysadmin)
	var sysUser User
	errSys := usersColl.FindOne(ctx, bson.M{"username": "sysadmin"}).Decode(&sysUser)
	if errSys != nil {
		sysPass := strings.TrimSpace(os.Getenv("INITIAL_SYSADMIN_PASSWORD"))
		if sysPass == "" {
			sysPass = generateSecureRandomPassword(16)
			log.Printf("🛡️ [SYSADMIN BOOTSTRAP] Tài khoản 'sysadmin' đã được tạo lần đầu với mật khẩu an toàn ngẫu nhiên. Vui lòng thiết lập INITIAL_SYSADMIN_PASSWORD trong biến môi trường để chỉ định mật khẩu mong muốn.")
		} else {
			log.Printf("🛡️ [SYSADMIN BOOTSTRAP] Khởi tạo tài khoản 'sysadmin' từ biến môi trường INITIAL_SYSADMIN_PASSWORD.")
		}

		hashedPass, err := bcrypt.GenerateFromPassword([]byte(sysPass), bcrypt.DefaultCost)
		if err == nil {
			sysadmin := User{
				Username:  "sysadmin",
				Password:  string(hashedPass),
				FullName:  "Tổng Quản Trị Hệ Thống",
				Role:      "systemadmin",
				CreatedAt: time.Now(),
			}
			res, err := usersColl.InsertOne(ctx, sysadmin)
			if err == nil {
				log.Printf("🛡️ [SYSADMIN READY] Khởi tạo tài khoản System Admin thành công (ID: %s)", res.InsertedID.(primitive.ObjectID).Hex())
				recordAccessLog("sysadmin", "systemadmin", "init_system", "127.0.0.1", "Khởi tạo tài khoản System Admin ban đầu an toàn")
			}
		}
	} else {
		log.Printf("🛡️ [SYSADMIN READY] Tài khoản System Admin 'sysadmin' đã sẵn sàng.")
	}

	// 2. Khởi tạo tài khoản admin01 (role: admin - được cấp quyền live)
	var adminUser User
	errAdmin := usersColl.FindOne(ctx, bson.M{"username": "admin01"}).Decode(&adminUser)
	if errAdmin != nil {
		adminPass := strings.TrimSpace(os.Getenv("INITIAL_ADMIN_PASSWORD"))
		if adminPass == "" {
			adminPass = generateSecureRandomPassword(16)
			log.Printf("👑 [ADMIN BOOTSTRAP] Tài khoản 'admin01' đã được tạo lần đầu với mật khẩu an toàn ngẫu nhiên. Vui lòng thiết lập INITIAL_ADMIN_PASSWORD trong biến môi trường để chỉ định mật khẩu mong muốn.")
		} else {
			log.Printf("👑 [ADMIN BOOTSTRAP] Khởi tạo tài khoản 'admin01' từ biến môi trường INITIAL_ADMIN_PASSWORD.")
		}

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(adminPass), bcrypt.DefaultCost)
		if err == nil {
			admin := User{
				Username:  "admin01",
				Password:  string(hashedPassword),
				FullName:  "Quản trị viên Streamer",
				Role:      "admin",
				CreatedAt: time.Now(),
			}
			res, err := usersColl.InsertOne(ctx, admin)
			if err == nil {
				log.Printf("👑 [ADMIN READY] Khởi tạo tài khoản Admin thành công (ID: %s)", res.InsertedID.(primitive.ObjectID).Hex())
			}
		}
	} else {
		log.Printf("👑 [ADMIN READY] Tài khoản Admin 'admin01' đã sẵn sàng.")
	}

	// Khởi tạo hai tài khoản chủ trại và dữ liệu danh mục trong MongoDB.
	ensureSeedAdmin := func(username, fullName, passwordEnv string) (primitive.ObjectID, bool) {
		var existing User
		if err := usersColl.FindOne(ctx, bson.M{"username": username}).Decode(&existing); err == nil {
			return existing.ID, true
		}
		password := strings.TrimSpace(os.Getenv(passwordEnv))
		if password == "" {
			password = generateSecureRandomPassword(16)
			log.Printf("[ADMIN BOOTSTRAP] Tài khoản '%s' tạo mật khẩu ngẫu nhiên. Đặt %s để chỉ định mật khẩu.", username, passwordEnv)
		}
		hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			log.Printf("[ADMIN BOOTSTRAP] Không thể mã hóa mật khẩu cho %s: %v", username, err)
			return primitive.NilObjectID, false
		}
		result, err := usersColl.InsertOne(ctx, User{Username: username, Password: string(hashed), FullName: fullName, Role: "admin", CreatedAt: time.Now()})
		if err != nil {
			log.Printf("[ADMIN BOOTSTRAP] Không thể tạo tài khoản %s: %v", username, err)
			return primitive.NilObjectID, false
		}
		return result.InsertedID.(primitive.ObjectID), true
	}

	seedAdmins := []struct {
		username string
		name     string
		key      string
		ms       string
		weight   string
		style    string
	}{
		{"admin05", "Chủ Trại Thành Trung 05", "thanhtrung05", "MS 501", "2.95 kg", "Lối ôm đấm kiềng hầu, đá mé giáp lưng"},
		{"admin06", "Chủ Trại Thành Trung 06", "thanhtrung06", "MS 601", "3.10 kg", "Mé xỏ ngang, đánh giáp lưng dạt sườn"},
	}
	for _, seed := range seedAdmins {
		adminID, ok := ensureSeedAdmin(seed.username, seed.name, "INITIAL_"+strings.ToUpper(seed.username)+"_PASSWORD")
		if !ok {
			continue
		}
		_, _ = keysColl.UpdateOne(ctx, bson.M{"key": seed.key}, bson.M{"$setOnInsert": StreamKey{
			Key: seed.key, Title: seed.name + " — Trực Tiếp Giao Lưu Chiến Kê", Streamer: seed.name,
			UserID: &adminID, IsActive: true, MS: seed.ms, Chang: seed.weight, Loi: seed.style, CreatedAt: time.Now(),
		}}, options.Update().SetUpsert(true))

		if chickensColl == nil {
			continue
		}
		count, _ := chickensColl.CountDocuments(ctx, bson.M{"created_by": seed.username})
		if count > 0 {
			continue
		}
		chicken := Chicken{
			ID: primitive.NewObjectID(), MS: seed.ms,
			Title: seed.name + " — Chiến kê giao lưu " + seed.weight,
			Breed: "don", BreedName: "Gà Đòn Long Biên Tuyển Chọn", Chang: seed.weight,
			Age: "11 tháng tơ", CanVay: "Huyền trâm đóng đúng chậu, chân vuông sừng", Loi: seed.style,
			DatNuoc: "Đã dạt 2 nước chuẩn", Price: 3500000, PriceText: "3.500.000 đ",
			Farm: seed.name, SellerName: seed.name, Location: "Long Biên, Hà Nội",
			Image:  "https://images.unsplash.com/photo-1548550023-2bdb3c5beed7?q=80&w=800&auto=format&fit=crop",
			Status: "available", UserID: &adminID, CreatedBy: seed.username, CreatedAt: time.Now(), UpdatedAt: time.Now(),
		}
		if _, err := chickensColl.InsertOne(ctx, chicken); err != nil {
			log.Printf("[CHICKEN SEED] Không thể tạo dữ liệu cho %s: %v", seed.username, err)
		}
	}
}

// createToken sinh chuỗi JWT token
func createToken(user User) (string, error) {
	return auth.CreateToken(user, jwtSecret)
}

// verifySRSWebhookSecret xác thực Secret Token cho các SRS Webhook (/auth, /auth/unpublish, /auth/dvr)
// Nếu biến môi trường SRS_WEBHOOK_SECRET được cấu hình, bắt buộc phải khớp qua Header X-SRS-Webhook-Secret hoặc query ?secret=
func verifySRSWebhookSecret(r *http.Request) bool {
	expected := strings.TrimSpace(os.Getenv("SRS_WEBHOOK_SECRET"))
	if expected == "" {
		return true
	}
	provided := strings.TrimSpace(r.Header.Get("X-SRS-Webhook-Secret"))
	if provided == "" {
		provided = strings.TrimSpace(r.URL.Query().Get("secret"))
	}
	if provided == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) == 1
}

var validUsernameRegex = auth.ValidUsernameRegex

// getUserFromAuthHeader trích xuất thông tin user từ Header Authorization
func getUserFromAuthHeader(r *http.Request) (*JWTClaims, error) {
	return auth.GetUserFromAuthHeader(r, jwtSecret)
}

// verifyStreamKey kiểm tra Stream Key hợp lệ trong MongoDB và bắt buộc chủ sở hữu phải có role == "admin"
// TÀI KHOẢN SYSTEMADMIN VÀ USER BÌNH THƯỜNG TUYỆT ĐỐI KHÔNG ĐƯỢC PHÉP LIVESTREAM
func verifyStreamKey(streamKey, publishSecret string) bool {
	mongoMutex.RLock()
	ready := isMongoReady
	coll := keysColl
	uColl := usersColl
	mongoMutex.RUnlock()

	if ready && coll != nil && uColl != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()

		var keyDoc StreamKey
		err := coll.FindOne(ctx, bson.M{"key": streamKey, "is_active": true}).Decode(&keyDoc)
		if err != nil {
			log.Printf("⛔ [AUTH BLOCKED] Phòng '%s' không tồn tại hoặc đã bị khóa", streamKey)
			return false
		}
		if !publishSecretMatches(publishSecret, keyDoc.PublishSecretHash) {
			log.Printf("⛔ [AUTH BLOCKED] Sai publish secret cho phòng '%s'", streamKey)
			return false
		}

		// YÊU CẦU: CHỈ CÓ TÀI KHOẢN CÓ ROLE LÀ ADMIN MỚI ĐƯỢC LIVESTREAM
		if keyDoc.UserID != nil {
			var u User
			if err := uColl.FindOne(ctx, bson.M{"_id": keyDoc.UserID}).Decode(&u); err == nil {
				if u.Role == "systemadmin" {
					log.Printf("⛔ [AUTH REJECTED] Phòng '%s' thuộc tài khoản SystemAdmin '%s'. Tài khoản SystemAdmin TUYỆT ĐỐI KHÔNG ĐƯỢC PHÉP LIVESTREAM!", streamKey, u.Username)
					return false
				}
				if u.Role != "admin" {
					log.Printf("⛔ [AUTH REJECTED] Phòng '%s' thuộc user '%s' (role: '%s'). Chỉ tài khoản role 'admin' mới được livestream!", streamKey, u.Username, u.Role)
					return false
				}
				log.Printf("👑 [AUTH APPROVED] Admin '%s' đang phát sóng phòng '%s'", u.Username, streamKey)
				return true
			}
			log.Printf("⛔ [AUTH BLOCKED] Không tìm thấy tài khoản sở hữu phòng '%s'", streamKey)
			return false
		}

		// Legacy key records may not have user_id; resolve their streamer label
		// against the accounts table, but still require the secret above.
		if keyDoc.Streamer != "" {
			var owner User
			ownerName := strings.ToLower(strings.TrimSpace(keyDoc.Streamer))
			ownerErr := uColl.FindOne(ctx, bson.M{"username": ownerName}).Decode(&owner)
			if ownerErr != nil {
				ownerErr = uColl.FindOne(ctx, bson.M{"full_name": keyDoc.Streamer}).Decode(&owner)
			}
			if ownerErr == nil && owner.Role == "admin" {
				log.Printf("👑 [AUTH APPROVED] Admin '%s' đang phát sóng phòng '%s'", owner.Username, streamKey)
				return true
			}
		}
		log.Printf("⛔ [AUTH BLOCKED] Phòng '%s' không thuộc tài khoản Admin nào", streamKey)
		return false
	}

	// Fail closed when the credential store is unavailable. Static default
	// room names are public identifiers and must never authorize publishing.
	log.Printf("⛔ [AUTH BLOCKED] Không thể xác thực phòng '%s' khi cơ sở dữ liệu không sẵn sàng", streamKey)
	return false
}

// verifyInternalABRStream only allows loopback FFmpeg publishers to publish
// generated renditions, and only for an existing active room owned by an admin.
func verifyInternalABRStream(app, streamKey, clientIP string) bool {
	if app != "abr" || (clientIP != "127.0.0.1" && clientIP != "::1" && clientIP != "localhost") {
		return false
	}

	roomKey := ""
	for _, suffix := range []string{"_720p", "_480p", "_360p"} {
		if strings.HasSuffix(streamKey, suffix) {
			roomKey = strings.TrimSuffix(streamKey, suffix)
			break
		}
	}
	if roomKey == "" {
		return false
	}

	mongoMutex.RLock()
	ready, coll, uColl := isMongoReady, keysColl, usersColl
	mongoMutex.RUnlock()
	if !ready || coll == nil || uColl == nil {
		return false
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var room StreamKey
	if err := coll.FindOne(ctx, bson.M{"key": roomKey, "is_active": true}).Decode(&room); err != nil {
		return false
	}
	var owner User
	if room.UserID != nil {
		if err := uColl.FindOne(ctx, bson.M{"_id": room.UserID}).Decode(&owner); err != nil {
			return false
		}
	} else {
		name := strings.ToLower(strings.TrimSpace(room.Streamer))
		if err := uColl.FindOne(ctx, bson.M{"username": name}).Decode(&owner); err != nil {
			if err := uColl.FindOne(ctx, bson.M{"full_name": room.Streamer}).Decode(&owner); err != nil {
				return false
			}
		}
	}
	return owner.Role == "admin"
}

// recordLiveSession ghi nhận phiên live mới và chốt các phiên cũ chưa đóng
func recordLiveSession(streamKey, app, clientIP string) {
	mongoMutex.RLock()
	ready := isMongoReady
	coll := sessionsColl
	kColl := keysColl
	mongoMutex.RUnlock()

	if !ready || coll == nil {
		return
	}

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		streamerName := "Admin"
		if kColl != nil {
			var kDoc StreamKey
			if err := kColl.FindOne(ctx, bson.M{"key": streamKey}).Decode(&kDoc); err == nil && kDoc.Streamer != "" {
				streamerName = kDoc.Streamer
			}
		}

		now := time.Now()
		// Đóng các session 'live' cũ của cùng stream key này
		_, _ = coll.UpdateMany(ctx,
			bson.M{"stream_key": streamKey, "status": "live"},
			bson.M{"$set": bson.M{"status": "ended", "ended_at": now}},
		)

		session := LiveSession{
			StreamKey: streamKey,
			Streamer:  streamerName,
			App:       app,
			ClientIP:  clientIP,
			Status:    "live",
			StartedAt: now,
		}
		_, _ = coll.InsertOne(ctx, session)
		recordAccessLog(streamerName, "admin", "start_stream", clientIP, fmt.Sprintf("Bắt đầu phát sóng luồng '%s' (App: %s)", streamKey, app))

		// Mỗi lần live mới bắt đầu: Phát lệnh reset kênh chat cho client (toàn bộ tin nhắn vẫn được lưu trữ vĩnh viễn trong DB)
		resetRoomChat(streamKey)
	}()
}

// unpublishHandler xử lý webhook khi luồng live dừng (từ SRS on_unpublish)
func unpublishHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	if !verifySRSWebhookSecret(r) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"code":403,"error":"Forbidden: Invalid SRS Webhook Secret"}`)
		return
	}

	limitRequestBody(w, r, SmallJSONMaxBodyBytes)
	var streamKey, clientAddr, appName string
	contentType := r.Header.Get("Content-Type")

	if strings.Contains(contentType, "application/json") {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, `{"error":"Payload too large"}`, http.StatusRequestEntityTooLarge)
			return
		}
		if len(body) > 0 {
			var payload SRSAuthPayload
			if err := json.Unmarshal(body, &payload); err == nil {
				streamKey = strings.TrimSpace(payload.Stream)
				if streamKey == "" {
					streamKey = strings.TrimSpace(payload.Name)
				}
				clientAddr = payload.IP
				appName = payload.App
			}
		}
	}

	if streamKey == "" {
		if err := r.ParseForm(); err == nil {
			streamKey = strings.TrimSpace(r.FormValue("stream"))
			if streamKey == "" {
				streamKey = strings.TrimSpace(r.FormValue("name"))
			}
			if clientAddr == "" {
				clientAddr = r.FormValue("addr")
			}
			if appName == "" {
				appName = r.FormValue("app")
			}
		}
	}

	if clientAddr == "" {
		clientAddr = getClientIP(r)
	}
	if appName == "abr" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"code":0}`)
		return
	}

	log.Printf("⏹️ [STREAM UNPUBLISH] Luồng live kết thúc - Key: '%s' | App: '%s' | Client: %s", streamKey, appName, clientAddr)

	mongoMutex.RLock()
	ready := isMongoReady
	coll := sessionsColl
	mongoMutex.RUnlock()

	if ready && coll != nil && streamKey != "" {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			var latest LiveSession
			opts := options.FindOne().SetSort(bson.M{"started_at": -1})
			err := coll.FindOne(ctx, bson.M{"stream_key": streamKey, "status": "live"}, opts).Decode(&latest)
			if err == nil {
				now := time.Now()
				duration := int64(now.Sub(latest.StartedAt).Seconds())
				if duration < 0 {
					duration = 0
				}
				_, _ = coll.UpdateOne(ctx, bson.M{"_id": latest.ID}, bson.M{
					"$set": bson.M{
						"status":           "ended",
						"ended_at":         now,
						"duration_seconds": duration,
					},
				})
				recordAccessLog(latest.Streamer, "admin", "stop_stream", clientAddr, fmt.Sprintf("Kết thúc luồng '%s'. Thời lượng: %d giây", streamKey, duration))
			}
			// Dừng bot tương tác trong phòng live khi streamer kết thúc live
			globalBotManager.StopBots(streamKey)

			// Luồng kết thúc: Phát lệnh reset kênh chat cho client (toàn bộ tin nhắn vẫn được lưu trữ vĩnh viễn trong DB)
			resetRoomChat(streamKey)
		}()
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `{"code":0}`)
}

// corsMiddleware xử lý CORS (theo danh sách ALLOWED_ORIGINS), HTTP Security Headers và giới hạn kích thước Body
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 1. Thiết lập các HTTP Security Headers chuẩn
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

		// 2. Kiểm tra Origin theo allowlist ALLOWED_ORIGINS (không dùng *)
		origin := strings.TrimSpace(r.Header.Get("Origin"))
		if origin != "" {
			if isOriginAllowed(origin, r.Host) {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Vary", "Origin")
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			} else if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusForbidden)
				return
			}
		}

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		// 3. Giới hạn kích thước request body mặc định (1 MB) chống DoS
		limitRequestBody(w, r, DefaultMaxBodyBytes)
		next.ServeHTTP(w, r)
	})
}

// ==================== AUTH CONTROLLERS ====================

// registerHandler cho phép người dùng tự do đăng ký tài khoản (Role: user)
func registerHandler(w http.ResponseWriter, r *http.Request) {
	userAuthHandler.Register(w, r)
}

// loginHandler đăng nhập tài khoản (hỗ trợ sysadmin, admin01 và user)
func loginHandler(w http.ResponseWriter, r *http.Request) {
	userAuthHandler.Login(w, r)
}

// logoutHandler ghi nhận khi người dùng đăng xuất và thu hồi JWT token
func logoutHandler(w http.ResponseWriter, r *http.Request) {
	userAuthHandler.Logout(w, r)
}

// meHandler trả về thông tin tài khoản đang đăng nhập
func meHandler(w http.ResponseWriter, r *http.Request) {
	userAuthHandler.Me(w, r)
}

// profileHandler xử lý xem và cập nhật thông tin hồ sơ cá nhân và avatar lưu trữ trong cơ sở dữ liệu MongoDB
func profileHandler(w http.ResponseWriter, r *http.Request) {
	userAuthHandler.Profile(w, r)
}

// ==================== STREAM KEY & SESSION CONTROLLERS ====================

// apiKeysHandler quản lý Stream Keys
func apiKeysHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		claims, err := getUserFromAuthHeader(r)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "Yêu cầu đăng nhập để truy cập danh sách Stream Keys"})
			return
		}
		if claims.Role != "admin" && claims.Role != "systemadmin" {
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{"error": "Quyền truy cập bị từ chối: Chỉ Quản trị viên mới được xem Stream Keys"})
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		var filter bson.M
		if claims.Role == "systemadmin" {
			filter = bson.M{}
		} else {
			// Admin chỉ xem các Stream Key do chính mình sở hữu
			objID, errID := primitive.ObjectIDFromHex(claims.UserID)
			if errID == nil {
				filter = bson.M{
					"$or": []bson.M{
						{"user_id": objID},
						{"streamer": claims.Username},
					},
				}
			} else {
				filter = bson.M{"streamer": claims.Username}
			}
		}

		if keysColl == nil {
			json.NewEncoder(w).Encode([]StreamKey{})
			return
		}

		cursor, err := keysColl.Find(ctx, filter)
		if err != nil {
			http.Error(w, `{"error":"Lỗi truy vấn"}`, http.StatusInternalServerError)
			return
		}
		defer cursor.Close(ctx)

		keys := make([]StreamKey, 0)
		_ = cursor.All(ctx, &keys)
		json.NewEncoder(w).Encode(keys)

	case http.MethodPost:
		// Tạo key mới (DÀNH CHO ADMIN HOẶC SYSTEMADMIN)
		claims, err := getUserFromAuthHeader(r)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "Yêu cầu đăng nhập"})
			return
		}
		if claims.Role != "admin" && claims.Role != "systemadmin" {
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{"error": "Chỉ tài khoản Admin hoặc SystemAdmin mới có quyền tạo Stream Key"})
			return
		}

		limitRequestBody(w, r, SmallJSONMaxBodyBytes)
		var req struct {
			Key           string `json:"key"`
			Title         string `json:"title"`
			Streamer      string `json:"streamer"`
			UserID        string `json:"user_id"`
			AdminUsername string `json:"admin_username"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":"Dữ liệu JSON không hợp lệ"}`, http.StatusBadRequest)
			return
		}

		cleanKey := strings.ToLower(strings.TrimSpace(req.Key))
		if cleanKey == "" {
			http.Error(w, `{"error":"Khóa luồng không được để trống"}`, http.StatusBadRequest)
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		var newKey StreamKey
		newKey.Key = cleanKey
		newKey.Title = strings.TrimSpace(req.Title)
		if newKey.Title == "" {
			newKey.Title = fmt.Sprintf("Kênh %s", cleanKey)
		}

		if claims.Role == "systemadmin" {
			// SystemAdmin tạo key và gán cho Admin được chỉ định
			var targetAdmin User
			var found bool

			// 1. Tìm theo user_id nếu có
			if req.UserID != "" {
				if objID, errID := primitive.ObjectIDFromHex(req.UserID); errID == nil {
					if errFind := usersColl.FindOne(ctx, bson.M{"_id": objID, "role": "admin"}).Decode(&targetAdmin); errFind == nil {
						found = true
					}
				}
			}

			// 2. Tìm theo admin_username
			if !found && req.AdminUsername != "" {
				if errFind := usersColl.FindOne(ctx, bson.M{"username": strings.ToLower(strings.TrimSpace(req.AdminUsername)), "role": "admin"}).Decode(&targetAdmin); errFind == nil {
					found = true
				}
			}

			// 3. Tìm theo streamer name
			if !found && req.Streamer != "" {
				if errFind := usersColl.FindOne(ctx, bson.M{"username": strings.ToLower(strings.TrimSpace(req.Streamer)), "role": "admin"}).Decode(&targetAdmin); errFind == nil {
					found = true
				}
			}

			// 4. Fallback tìm bất kỳ admin nào
			if !found {
				_ = usersColl.FindOne(ctx, bson.M{"role": "admin"}).Decode(&targetAdmin)
			}

			if targetAdmin.ID != primitive.NilObjectID {
				newKey.UserID = &targetAdmin.ID
				newKey.Streamer = targetAdmin.FullName
				if newKey.Streamer == "" {
					newKey.Streamer = targetAdmin.Username
				}
			} else {
				newKey.Streamer = "Admin"
			}
		} else {
			// Admin tự tạo key cho mình
			objID, _ := primitive.ObjectIDFromHex(claims.UserID)
			newKey.UserID = &objID
			newKey.Streamer = claims.Username
		}
		newKey.IsActive = true
		newKey.CreatedAt = time.Now()

		newKey, insertErr := insertStreamKey(ctx, newKey)
		if insertErr != nil {
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(map[string]string{"error": "Stream Key này đã tồn tại!"})
			return
		}
		recordAccessLog(claims.Username, claims.Role, "create_key", getClientIP(r),
			fmt.Sprintf("Tạo khóa luồng mới '%s' cho Streamer '%s'", newKey.Key, newKey.Streamer))

		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(newKey)

	case http.MethodDelete:
		// Xóa Stream Key (dành cho Admin hoặc SystemAdmin)
		claims, err := getUserFromAuthHeader(r)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "Yêu cầu đăng nhập để thực hiện thao tác"})
			return
		}
		if claims.Role != "admin" && claims.Role != "systemadmin" {
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{"error": "Quyền truy cập bị từ chối: Chỉ Quản trị viên mới được xóa Stream Key"})
			return
		}

		keyParam := strings.TrimSpace(r.URL.Query().Get("key"))
		if keyParam == "" {
			http.Error(w, `{"error":"Thiếu tham số key"}`, http.StatusBadRequest)
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if keysColl == nil {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"error": "Không tìm thấy khóa luồng"})
			return
		}

		// 1. Tìm thông tin Stream Key mục tiêu
		var targetKey StreamKey
		errFind := keysColl.FindOne(ctx, bson.M{"key": keyParam}).Decode(&targetKey)
		if errFind != nil {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"error": "Không tìm thấy khóa luồng"})
			return
		}

		// 2. Kiểm tra quyền sở hữu (IDOR protection)
		// Admin CHỈ ĐƯỢC PHÉP xóa key của chính mình; SystemAdmin được xóa mọi key
		if claims.Role != "systemadmin" {
			callerObjID, errID := primitive.ObjectIDFromHex(claims.UserID)
			if errID != nil {
				w.WriteHeader(http.StatusForbidden)
				json.NewEncoder(w).Encode(map[string]string{"error": "Quyền truy cập bị từ chối: ID người dùng không hợp lệ"})
				return
			}

			// Kiểm tra user_id trong MongoDB
			isOwner := false
			if targetKey.UserID != nil && *targetKey.UserID == callerObjID {
				isOwner = true
			}

			if !isOwner {
				w.WriteHeader(http.StatusForbidden)
				json.NewEncoder(w).Encode(map[string]string{"error": "Quyền truy cập bị từ chối: Bạn không sở hữu Stream Key này"})
				return
			}
		}

		res, err := keysColl.DeleteOne(ctx, bson.M{"_id": targetKey.ID})
		if err != nil || res.DeletedCount == 0 {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "Không thể xóa khóa"})
			return
		}

		recordAccessLog(claims.Username, claims.Role, "delete_key", getClientIP(r),
			fmt.Sprintf("Xóa khóa luồng '%s'", keyParam))

		json.NewEncoder(w).Encode(map[string]string{"message": "Đã xóa Stream Key thành công"})

	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

// revealPublishSecretHandler only returns the decrypted credential after an
// authenticated owner explicitly requests it. List APIs never include it.
func revealPublishSecretHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store, max-age=0")
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	claims, err := getUserFromAuthHeader(r)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "Yêu cầu đăng nhập"})
		return
	}
	if claims.Role != "admin" && claims.Role != "systemadmin" {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"error": "Chỉ Admin mới được xem khóa phát"})
		return
	}
	if keysColl == nil {
		http.Error(w, `{"error":"Cơ sở dữ liệu chưa sẵn sàng"}`, http.StatusServiceUnavailable)
		return
	}
	id, err := primitive.ObjectIDFromHex(strings.TrimSpace(r.URL.Query().Get("id")))
	if err != nil {
		http.Error(w, `{"error":"ID khóa không hợp lệ"}`, http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	targetKey, err := findStreamKeyByID(ctx, id)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "Không tìm thấy khóa phát"})
		return
	}
	if claims.Role != "systemadmin" {
		callerID, errID := primitive.ObjectIDFromHex(claims.UserID)
		ownsKey := errID == nil && targetKey.UserID != nil && *targetKey.UserID == callerID
		if !ownsKey && targetKey.UserID == nil {
			ownsKey = strings.EqualFold(targetKey.Streamer, claims.Username)
		}
		if !ownsKey {
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{"error": "Bạn không sở hữu khóa phát này"})
			return
		}
	}
	if err := hydratePublishSecret(&targetKey); err != nil {
		http.Error(w, `{"error":"Không thể mở khóa phát"}`, http.StatusInternalServerError)
		return
	}
	recordAccessLog(claims.Username, claims.Role, "reveal_publish_secret", getClientIP(r), fmt.Sprintf("Xem khóa phát của phòng '%s'", targetKey.Key))
	json.NewEncoder(w).Encode(map[string]string{"publish_secret": targetKey.PublishSecret})
}

// toggleKeyHandler cho phép Admin bật/tắt Stream Key của chính mình (hoặc SystemAdmin bật/tắt mọi Stream Key)
func toggleKeyHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPatch && r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	claims, err := getUserFromAuthHeader(r)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "Yêu cầu đăng nhập"})
		return
	}
	if claims.Role != "admin" && claims.Role != "systemadmin" {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"error": "Chỉ Quản trị viên (Admin hoặc SystemAdmin) mới có quyền bật/tắt Key"})
		return
	}

	limitRequestBody(w, r, SmallJSONMaxBodyBytes)
	var req struct {
		Key      string `json:"key"`
		IsActive bool   `json:"is_active"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Dữ liệu không hợp lệ"}`, http.StatusBadRequest)
		return
	}

	req.Key = strings.TrimSpace(req.Key)
	if req.Key == "" {
		http.Error(w, `{"error":"Thiếu tham số key"}`, http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Kiểm tra quyền sở hữu Stream Key (chống IDOR: tránh admin02 khóa key của admin01)
	if keysColl != nil {
		var targetKey StreamKey
		if errFind := keysColl.FindOne(ctx, bson.M{"key": req.Key}).Decode(&targetKey); errFind != nil {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"error": "Không tìm thấy khóa luồng"})
			return
		}
		if claims.Role != "systemadmin" {
			callerObjID, errID := primitive.ObjectIDFromHex(claims.UserID)
			if errID != nil || targetKey.UserID == nil || *targetKey.UserID != callerObjID {
				w.WriteHeader(http.StatusForbidden)
				json.NewEncoder(w).Encode(map[string]string{"error": "Quyền truy cập bị từ chối: Bạn không sở hữu Stream Key này"})
				return
			}
		}

		_, err = keysColl.UpdateOne(ctx, bson.M{"_id": targetKey.ID}, bson.M{"$set": bson.M{"is_active": req.IsActive}})
		if err != nil {
			http.Error(w, `{"error":"Lỗi cập nhật"}`, http.StatusInternalServerError)
			return
		}
	} else {
		if !canAdminManageStreamOrSession(ctx, claims, req.Key, "") {
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{"error": "Quyền truy cập bị từ chối: Bạn không sở hữu Stream Key này"})
			return
		}
	}

	recordAccessLog(claims.Username, claims.Role, "toggle_key", getClientIP(r),
		fmt.Sprintf("Cập nhật trạng thái khóa '%s' thành %v", req.Key, req.IsActive))

	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":   "Cập nhật trạng thái thành công!",
		"key":       req.Key,
		"is_active": req.IsActive,
	})
}

// apiSessionsHandler xem lịch sử phiên live (Admin xem của mình, SystemAdmin xem toàn bộ, bảo vệ IP streamer)
func apiSessionsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	claims, err := getUserFromAuthHeader(r)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "Yêu cầu đăng nhập để truy cập lịch sử phiên live"})
		return
	}
	if claims.Role != "admin" && claims.Role != "systemadmin" {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"error": "Quyền truy cập bị từ chối"})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var filter bson.M
	if claims.Role == "systemadmin" {
		filter = bson.M{}
	} else {
		// Admin chỉ xem lịch sử live của chính mình
		filter = bson.M{
			"$or": []bson.M{
				{"streamer": claims.Username},
				{"stream_key": claims.Username},
			},
		}
	}

	if sessionsColl == nil {
		json.NewEncoder(w).Encode([]interface{}{})
		return
	}

	opts := options.Find().SetSort(bson.M{"started_at": -1}).SetLimit(50)
	cursor, err := sessionsColl.Find(ctx, filter, opts)
	if err != nil {
		http.Error(w, `{"error":"Lỗi truy vấn sessions"}`, http.StatusInternalServerError)
		return
	}
	defer cursor.Close(ctx)

	var sessions []LiveSession
	_ = cursor.All(ctx, &sessions)

	// Bảo vệ quyền riêng tư: Mặt nạ hóa địa chỉ IP streamer
	type SafeLiveSession struct {
		ID              primitive.ObjectID `json:"id"`
		StreamKey       string             `json:"stream_key"`
		Streamer        string             `json:"streamer"`
		Title           string             `json:"title,omitempty"`
		App             string             `json:"app"`
		ClientIP        string             `json:"client_ip"`
		Status          string             `json:"status"`
		StartedAt       time.Time          `json:"started_at"`
		EndedAt         *time.Time         `json:"ended_at,omitempty"`
		DurationSeconds int64              `json:"duration_seconds"`
		ReplayURL       string             `json:"replay_url,omitempty"`
		DriveFileID     string             `json:"drive_file_id,omitempty"`
		RecordStatus    string             `json:"record_status,omitempty"`
	}

	safeSessions := make([]SafeLiveSession, 0, len(sessions))
	for _, s := range sessions {
		clientIP := "***"
		if claims.Role == "systemadmin" {
			clientIP = maskIP(s.ClientIP)
		}
		safeSessions = append(safeSessions, SafeLiveSession{
			ID:              s.ID,
			StreamKey:       s.StreamKey,
			Streamer:        s.Streamer,
			Title:           s.Title,
			App:             s.App,
			ClientIP:        clientIP,
			Status:          s.Status,
			StartedAt:       s.StartedAt,
			EndedAt:         s.EndedAt,
			DurationSeconds: s.DurationSeconds,
			ReplayURL:       s.ReplayURL,
			DriveFileID:     s.DriveFileID,
			RecordStatus:    s.RecordStatus,
		})
	}

	json.NewEncoder(w).Encode(safeSessions)
}

// apiUsersHandler danh sách người dùng (Admin & SystemAdmin có thể xem)
func apiUsersHandler(w http.ResponseWriter, r *http.Request) {
	userAuthHandler.ListUsers(w, r)
}

// ==================== SYSTEM ADMIN CONTROLLERS ====================

// requireSystemAdmin xác thực token và kiểm tra role == "systemadmin"
func requireSystemAdmin(r *http.Request) (*JWTClaims, error) {
	claims, err := getUserFromAuthHeader(r)
	if err != nil {
		return nil, fmt.Errorf("chưa đăng nhập hoặc phiên làm việc hết hạn")
	}
	if claims.Role != "systemadmin" {
		return nil, fmt.Errorf("truy cập bị từ chối: Chỉ tài khoản Tổng Quản Trị (SystemAdmin) mới có quyền!")
	}
	return claims, nil
}

// sysadminUsersHandler quản trị danh sách người dùng, tạo tài khoản Admin mới, đổi role, xóa tài khoản
func sysadminUsersHandler(w http.ResponseWriter, r *http.Request) {
	userAuthHandler.SysadminUsers(w, r)
}

// sysadminLogsHandler trả về lịch sử vào/ra và các thao tác trong hệ thống
func sysadminLogsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, err := requireSystemAdmin(r)
	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	filter := bson.M{}
	actionFilter := r.URL.Query().Get("action")
	if actionFilter != "" {
		filter["action"] = actionFilter
	}
	userFilter := r.URL.Query().Get("username")
	if userFilter != "" {
		filter["username"] = userFilter
	}

	opts := options.Find().SetSort(bson.M{"created_at": -1}).SetLimit(100)
	cursor, err := accessLogsColl.Find(ctx, filter, opts)
	if err != nil {
		http.Error(w, `{"error":"Lỗi truy vấn logs"}`, http.StatusInternalServerError)
		return
	}
	defer cursor.Close(ctx)

	var logs []AccessLog
	_ = cursor.All(ctx, &logs)
	json.NewEncoder(w).Encode(logs)
}

// sysadminLiveStatsHandler trả về thống kê tổng hợp giờ live, tần suất và danh sách phiên live
func sysadminLiveStatsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, err := requireSystemAdmin(r)
	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 1. Lấy tất cả phiên live gần nhất
	opts := options.Find().SetSort(bson.M{"started_at": -1}).SetLimit(200)
	cursor, err := sessionsColl.Find(ctx, bson.M{}, opts)
	if err != nil {
		http.Error(w, `{"error":"Lỗi truy vấn"}`, http.StatusInternalServerError)
		return
	}
	defer cursor.Close(ctx)

	var allSessions []LiveSession
	_ = cursor.All(ctx, &allSessions)

	var totalDurationSeconds int64 = 0
	activeSessions := 0
	type StreamerSummary struct {
		Streamer             string    `json:"streamer"`
		StreamKey            string    `json:"stream_key"`
		TotalSessions        int       `json:"total_sessions"`
		TotalDurationSeconds int64     `json:"total_duration_seconds"`
		LastLiveAt           time.Time `json:"last_live_at"`
		IsLive               bool      `json:"is_live"`
	}

	type DailySummary struct {
		Date                 string `json:"date"`
		SessionCount         int    `json:"session_count"`
		TotalDurationSeconds int64  `json:"total_duration_seconds"`
	}

	streamerMap := make(map[string]*StreamerSummary)
	dailyMap := make(map[string]*DailySummary)

	for _, s := range allSessions {
		duration := s.DurationSeconds
		if s.Status == "live" {
			activeSessions++
			// Tính thời gian tạm thời cho phiên đang diễn ra
			duration = int64(time.Since(s.StartedAt).Seconds())
		}
		totalDurationSeconds += duration

		// Gom nhóm theo Streamer / Key
		groupKey := s.Streamer
		if groupKey == "" {
			groupKey = s.StreamKey
		}
		if _, ok := streamerMap[groupKey]; !ok {
			streamerMap[groupKey] = &StreamerSummary{
				Streamer:   groupKey,
				StreamKey:  s.StreamKey,
				LastLiveAt: s.StartedAt,
			}
		}
		summary := streamerMap[groupKey]
		summary.TotalSessions++
		summary.TotalDurationSeconds += duration
		if s.StartedAt.After(summary.LastLiveAt) {
			summary.LastLiveAt = s.StartedAt
		}
		if s.Status == "live" {
			summary.IsLive = true
		}

		// Gom nhóm theo Ngày (YYYY-MM-DD)
		dateStr := s.StartedAt.Format("2006-01-02")
		if _, ok := dailyMap[dateStr]; !ok {
			dailyMap[dateStr] = &DailySummary{Date: dateStr}
		}
		dSum := dailyMap[dateStr]
		dSum.SessionCount++
		dSum.TotalDurationSeconds += duration
	}

	var streamerList []StreamerSummary
	for _, v := range streamerMap {
		streamerList = append(streamerList, *v)
	}

	// 7 ngày gần nhất
	var dailyList []DailySummary
	for i := 6; i >= 0; i-- {
		d := time.Now().AddDate(0, 0, -i).Format("2006-01-02")
		if ds, ok := dailyMap[d]; ok {
			dailyList = append(dailyList, *ds)
		} else {
			dailyList = append(dailyList, DailySummary{
				Date:                 d,
				SessionCount:         0,
				TotalDurationSeconds: 0,
			})
		}
	}

	// Đếm tổng users và admins
	userCount, _ := usersColl.CountDocuments(ctx, bson.M{})
	adminCount, _ := usersColl.CountDocuments(ctx, bson.M{"role": "admin"})

	json.NewEncoder(w).Encode(map[string]interface{}{
		"total_sessions":         len(allSessions),
		"total_duration_seconds": totalDurationSeconds,
		"active_sessions":        activeSessions,
		"total_users":            userCount,
		"total_admins":           adminCount,
		"streamer_stats":         streamerList,
		"daily_stats":            dailyList,
		"sessions":               allSessions,
	})
}

// ==================== SRS WEBHOOK ====================

// authHandler xử lý webhook xác thực từ SRS hoặc Nginx-RTMP
func authHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	if !verifySRSWebhookSecret(r) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"code":403,"error":"Forbidden: Invalid SRS Webhook Secret"}`)
		return
	}

	limitRequestBody(w, r, SmallJSONMaxBodyBytes)
	var streamKey, publishSecret, clientAddr, appName, param string
	contentType := r.Header.Get("Content-Type")

	// 1. Parse JSON từ SRS Media Server
	if strings.Contains(contentType, "application/json") {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, `{"error":"Payload too large"}`, http.StatusRequestEntityTooLarge)
			return
		}
		if len(body) > 0 {
			var payload SRSAuthPayload
			if err := json.Unmarshal(body, &payload); err == nil {
				streamKey = strings.TrimSpace(payload.Stream)
				if streamKey == "" {
					streamKey = strings.TrimSpace(payload.Name)
				}
				clientAddr = payload.IP
				appName = payload.App
				param = payload.Param
			}
		}
	}

	// 2. Parse Form-data từ Nginx-RTMP
	if streamKey == "" {
		if err := r.ParseForm(); err == nil {
			streamKey = strings.TrimSpace(r.FormValue("stream"))
			if streamKey == "" {
				streamKey = strings.TrimSpace(r.FormValue("name"))
			}
			if clientAddr == "" {
				clientAddr = r.FormValue("addr")
			}
			if appName == "" {
				appName = r.FormValue("app")
			}
			param = r.FormValue("param")
			publishSecret = r.FormValue("publish_secret")
		} else if strings.Contains(err.Error(), "http: request body too large") {
			http.Error(w, `{"error":"Payload too large"}`, http.StatusRequestEntityTooLarge)
			return
		}
	}

	if clientAddr == "" {
		clientAddr = getClientIP(r)
	}
	if publishSecret == "" {
		publishSecret = publishSecretFromSRSParam(param)
	}

	// Kiểm tra tính hợp lệ và đang hoạt động trong MongoDB
	if streamKey != "" && verifyInternalABRStream(appName, streamKey, clientAddr) {
		log.Printf("[AUTH SUCCESS] Internal ABR rendition allowed - Room rendition: '%s'", streamKey)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"code":0}`)
		return
	}

	if streamKey != "" && appName != "abr" && verifyStreamKey(streamKey, publishSecret) {
		log.Printf("[AUTH SUCCESS] Stream allowed (MongoDB verified) - Room: '%s' | App: '%s' | Client: %s", streamKey, appName, clientAddr)
		recordLiveSession(streamKey, appName, clientAddr)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"code":0}`)
		return
	}

	log.Printf("[AUTH FAILED] Stream denied - Room: '%s' (không hợp lệ hoặc publish secret sai) | Client: %s", streamKey, clientAddr)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	fmt.Fprint(w, `{"code":403,"error":"Forbidden: Invalid or Disabled Stream Key"}`)
}

// healthHandler kiểm tra trạng thái hoạt động của server và MongoDB
func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	mongoMutex.RLock()
	ready := isMongoReady
	mongoMutex.RUnlock()

	status := map[string]interface{}{
		"status":    "healthy",
		"service":   "Livestream Auth & Role Gateway",
		"mongodb":   ready,
		"timestamp": time.Now().Format(time.RFC3339),
	}
	json.NewEncoder(w).Encode(status)
}

func main() {
	// Khởi tạo rate limiters
	limiter.InitRateLimiters()

	// Khởi tạo MongoDB và seed tài khoản admin01 / 123456
	initMongoDB()

	mux := http.NewServeMux()

	// Webhook cho SRS Media Server (bắt đầu live, kết thúc live & lưu bản ghi DVR)
	mux.HandleFunc("/auth", authHandler)
	mux.HandleFunc("/auth/unpublish", unpublishHandler)
	mux.HandleFunc("/auth/dvr", dvrHandler)

	// APIs Xác thực người dùng (Auth)
	mux.HandleFunc("/api/auth/register", registerHandler)
	mux.HandleFunc("/api/auth/login", loginHandler)
	mux.HandleFunc("/api/auth/logout", logoutHandler)
	mux.HandleFunc("/api/auth/me", meHandler)
	mux.HandleFunc("/api/auth/profile", profileHandler)
	mux.HandleFunc("/api/user/profile", profileHandler)

	// APIs Quản lý Stream Keys, Sessions & Video Xem Lại (Replays)
	mux.HandleFunc("/api/keys", apiKeysHandler)
	mux.HandleFunc("/api/keys/secret", revealPublishSecretHandler)
	mux.HandleFunc("/api/keys/toggle", toggleKeyHandler)
	mux.HandleFunc("/api/sessions", apiSessionsHandler)
	mux.HandleFunc("/api/sessions/replay", apiSessionReplayManageHandler)
	mux.HandleFunc("/api/sessions/archive", archiveReplayHandler)
	mux.HandleFunc("/api/replays", apiReplaysHandler)
	mux.HandleFunc("/api/users", apiUsersHandler)
	mux.HandleFunc("/health", healthHandler)

	// APIs Chợ Gà Ba Miền (Lưu trữ MongoDB thật 100%)
	mux.HandleFunc("/api/chickens", apiChickensHandler)

	// APIs Danh sách phòng live công khai cho người xem (MongoDB stream_keys thật)
	mux.HandleFunc("/api/rooms", apiPublicRoomsHandler)
	mux.HandleFunc("/api/public/rooms", apiPublicRoomsHandler)

	// APIs Quản trị cấp cao System Admin
	mux.HandleFunc("/api/sysadmin/users", sysadminUsersHandler)
	mux.HandleFunc("/api/sysadmin/users/role", sysadminUsersHandler)
	mux.HandleFunc("/api/sysadmin/logs", sysadminLogsHandler)
	mux.HandleFunc("/api/sysadmin/live-stats", sysadminLiveStatsHandler)

	// Real-time Chat WebSocket & REST APIs
	mux.HandleFunc("/ws/chat", wsChatHandler)
	mux.HandleFunc("/api/chat/history", apiChatHistoryHandler)

	// APIs Quản lý Bot Tương Tác (Chat Bots & Room Seeding)
	mux.HandleFunc("/api/sysadmin/bots", sysadminBotsHandler)
	mux.HandleFunc("/api/admin/bots", adminAvailableBotsHandler)
	mux.HandleFunc("/api/admin/room-bots", adminRoomBotsHandler)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8000"
	}
	addr := ":" + port

	server := &http.Server{
		Addr:              addr,
		Handler:           corsMiddleware(mux),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	log.Printf("🚀 Livestream Auth & Role-based Server đang chạy trên cổng %s...", addr)
	log.Printf("💬 Kênh Live Chat WebSocket: ws://localhost%s/ws/chat?streamKey=...", addr)
	log.Printf("🛡️ Hệ thống bảo mật: Vui lòng đăng nhập với tài khoản System Admin hoặc Admin Streamer đã cấp.")
	log.Printf("👤 Đăng ký người dùng mới: POST http://localhost%s/api/auth/register", addr)

	// Khởi động HTTPS Server trên cổng :8443 nếu có file chứng chỉ SSL (cho thiết bị di động/iPhone)
	if _, errC := os.Stat("server.crt"); errC == nil {
		if _, errK := os.Stat("server.key"); errK == nil {
			go func() {
				httpsServer := &http.Server{
					Addr:              ":8443",
					Handler:           corsMiddleware(mux),
					ReadHeaderTimeout: 5 * time.Second,
					IdleTimeout:       120 * time.Second,
				}
				log.Printf("🔒 HTTPS API & Secure WebSocket đang chạy trên cổng :8443 (wss://localhost:8443/ws/chat)")
				if err := httpsServer.ListenAndServeTLS("server.crt", "server.key"); err != nil && err != http.ErrServerClosed {
					log.Printf("⚠️ Lỗi khởi động HTTPS trên cổng :8443: %v", err)
				}
			}()
		}
	}

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("❌ Lỗi khởi động server: %v", err)
	}
}
