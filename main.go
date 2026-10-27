package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"crypto/rand"
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
	"livestream-be/internal/stream"
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
	return stream.StreamKeyCredentials(keys)
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


var streamHandler = stream.NewHandler(
	func() *store.Store { return globalStore },
	func() []byte { return jwtSecret },
	verifySRSWebhookSecret,
	publishSecretMatches,
	publishSecretFromSRSParam,
	hydratePublishSecret,
	streamKeyForStorage,
	findStreamKeyByID,
	insertStreamKey,
	recordAccessLog,
	resetRoomChat,
	func(room string) {
		if globalBotManager != nil {
			globalBotManager.StopBots(room)
		}
	},
	canAdminManageStreamOrSession,
)

// maskIP che giấu địa chỉ IP của streamer để bảo vệ quyền riêng tư
func maskIP(ip string) string {
	return stream.MaskIP(ip)
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
	return stream.GenerateStreamKey()
}

// ensureAdminStreamKeys migrates username-based legacy keys and creates a key
// for admins that do not have one yet.
func ensureAdminStreamKeys(ctx context.Context, user User) ([]StreamKey, error) {
	return streamHandler.EnsureAdminStreamKeys(ctx, user)
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
func verifySRSWebhookSecret(r *http.Request) bool {
	return stream.VerifySRSWebhookSecret(r)
}

var validUsernameRegex = auth.ValidUsernameRegex

// getUserFromAuthHeader trích xuất thông tin user từ Header Authorization
func getUserFromAuthHeader(r *http.Request) (*JWTClaims, error) {
	return auth.GetUserFromAuthHeader(r, jwtSecret)
}

// verifyStreamKey kiểm tra Stream Key hợp lệ trong MongoDB và bắt buộc chủ sở hữu phải có role == "admin"
func verifyStreamKey(streamKey, publishSecret string) bool {
	return stream.VerifyStreamKey(context.Background(), globalStore, streamKey, publishSecret, publishSecretMatches)
}

// verifyInternalABRStream only allows loopback FFmpeg publishers to publish
func verifyInternalABRStream(app, streamKey, clientIP string) bool {
	return stream.VerifyInternalABRStream(context.Background(), globalStore, app, streamKey, clientIP)
}

// recordLiveSession ghi nhận phiên live mới và chốt các phiên cũ chưa đóng
func recordLiveSession(streamKey, app, clientIP string) {
	streamHandler.RecordLiveSession(streamKey, app, clientIP)
}

// unpublishHandler xử lý webhook khi luồng live dừng (từ SRS on_unpublish)
func unpublishHandler(w http.ResponseWriter, r *http.Request) {
	streamHandler.Unpublish(w, r)
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
	streamHandler.Keys(w, r)
}

// revealPublishSecretHandler only returns the decrypted credential after an
// authenticated owner explicitly requests it. List APIs never include it.
func revealPublishSecretHandler(w http.ResponseWriter, r *http.Request) {
	streamHandler.RevealPublishSecret(w, r)
}

// toggleKeyHandler cho phép Admin bật/tắt Stream Key của chính mình (hoặc SystemAdmin bật/tắt mọi Stream Key)
func toggleKeyHandler(w http.ResponseWriter, r *http.Request) {
	streamHandler.ToggleKey(w, r)
}

// apiSessionsHandler xem lịch sử phiên live (Admin xem của mình, SystemAdmin xem toàn bộ, bảo vệ IP streamer)
func apiSessionsHandler(w http.ResponseWriter, r *http.Request) {
	streamHandler.Sessions(w, r)
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
	streamHandler.Auth(w, r)
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
