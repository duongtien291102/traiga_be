package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"

	"livestream-be/internal/model"
	"livestream-be/internal/security/limiter"
	"livestream-be/internal/security/token"
	"livestream-be/internal/store"
)

// Handler quản lý các HTTP endpoints về đăng ký, đăng nhập, hồ sơ người dùng và quản trị user.
type Handler struct {
	GetStore              func() *store.Store
	GetJwtSecret          func() []byte
	RecordAccessLog       func(username, role, action, ip, details string)
	EnsureAdminStreamKeys func(ctx context.Context, user model.User) ([]model.StreamKey, error)
	GenerateStreamKey     func() (string, error)
	InsertStreamKey       func(ctx context.Context, key model.StreamKey) (model.StreamKey, error)
}

// NewHandler tạo mới Auth Handler.
func NewHandler(
	getStore func() *store.Store,
	getJwtSecret func() []byte,
	recordAccessLog func(username, role, action, ip, details string),
	ensureAdminStreamKeys func(ctx context.Context, user model.User) ([]model.StreamKey, error),
	generateStreamKey func() (string, error),
	insertStreamKey func(ctx context.Context, key model.StreamKey) (model.StreamKey, error),
) *Handler {
	return &Handler{
		GetStore:              getStore,
		GetJwtSecret:          getJwtSecret,
		RecordAccessLog:       recordAccessLog,
		EnsureAdminStreamKeys: ensureAdminStreamKeys,
		GenerateStreamKey:     generateStreamKey,
		InsertStreamKey:       insertStreamKey,
	}
}

func (h *Handler) getSecret() []byte {
	if h.GetJwtSecret != nil {
		return h.GetJwtSecret()
	}
	return nil
}

func (h *Handler) getUser(r *http.Request) (*model.JWTClaims, error) {
	return GetUserFromAuthHeader(r, h.getSecret())
}

func (h *Handler) requireSystemAdmin(r *http.Request) (*model.JWTClaims, error) {
	claims, err := h.getUser(r)
	if err != nil {
		return nil, fmt.Errorf("chưa đăng nhập hoặc phiên làm việc hết hạn")
	}
	if claims.Role != "systemadmin" {
		return nil, fmt.Errorf("truy cập bị từ chối: Chỉ tài khoản Tổng Quản Trị (SystemAdmin) mới có quyền!")
	}
	return claims, nil
}

func streamKeyCredentials(keys []model.StreamKey) []model.StreamKeyCredential {
	credentials := make([]model.StreamKeyCredential, 0, len(keys))
	for _, key := range keys {
		credentials = append(credentials, model.StreamKeyCredential{StreamKey: key, PublishSecret: key.PublishSecret})
	}
	return credentials
}

// Register xử lý đăng ký tài khoản người dùng mới.
// POST /api/auth/register
func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	limiter.InitRateLimiters()
	clientIP := limiter.GetClientIP(r)
	if limiter.RegisterLimiter != nil && !limiter.RegisterLimiter.Allow(clientIP) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Retry-After", "60")
		w.WriteHeader(http.StatusTooManyRequests)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error": "Quá nhiều yêu cầu đăng ký từ địa chỉ này. Vui lòng thử lại sau 1 phút.",
		})
		return
	}

	limiter.LimitRequestBody(w, r, limiter.SmallJSONMaxBodyBytes)
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		FullName string `json:"full_name"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Dữ liệu không hợp lệ hoặc vượt quá dung lượng cho phép"}`, http.StatusBadRequest)
		return
	}

	req.Username = strings.ToLower(strings.TrimSpace(req.Username))
	req.Password = strings.TrimSpace(req.Password)
	req.FullName = strings.TrimSpace(req.FullName)
	if req.Username == "" || req.Password == "" {
		http.Error(w, `{"error":"Tên đăng nhập và mật khẩu không được để trống"}`, http.StatusBadRequest)
		return
	}

	if !ValidUsernameRegex.MatchString(req.Username) {
		http.Error(w, `{"error":"Tên đăng nhập phải từ 3 đến 32 ký tự và chỉ chứa chữ cái thường, số, dấu chấm, gạch ngang hoặc gạch dưới"}`, http.StatusBadRequest)
		return
	}
	if len(req.Password) < 6 || len(req.Password) > 72 {
		http.Error(w, `{"error":"Mật khẩu phải có độ dài từ 6 đến 72 ký tự"}`, http.StatusBadRequest)
		return
	}
	if len(req.FullName) > 100 {
		http.Error(w, `{"error":"Họ tên không được vượt quá 100 ký tự"}`, http.StatusBadRequest)
		return
	}

	st := h.GetStore()
	if st == nil || st.Users == nil {
		http.Error(w, `{"error":"Cơ sở dữ liệu chưa sẵn sàng"}`, http.StatusServiceUnavailable)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var existing model.User
	if err := st.Users.FindOne(ctx, bson.M{"username": req.Username}).Decode(&existing); err == nil {
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "Tên đăng nhập này đã được sử dụng"})
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, `{"error":"Lỗi mã hóa mật khẩu"}`, http.StatusInternalServerError)
		return
	}

	fullName := req.FullName
	if fullName == "" {
		fullName = req.Username
	}

	newUser := model.User{
		Username:  req.Username,
		Password:  string(hashedPassword),
		FullName:  fullName,
		Role:      "user",
		CreatedAt: time.Now(),
	}

	res, err := st.Users.InsertOne(ctx, newUser)
	if err != nil {
		http.Error(w, `{"error":"Không thể lưu người dùng"}`, http.StatusInternalServerError)
		return
	}
	newUser.ID = res.InsertedID.(primitive.ObjectID)

	if h.RecordAccessLog != nil {
		h.RecordAccessLog(newUser.Username, newUser.Role, "register", clientIP, "Đăng ký tài khoản mới")
	}

	jwtToken, _ := CreateToken(newUser, h.getSecret())
	token.Global().SetActiveUserToken(newUser.Username, jwtToken, time.Now().Add(7*24*time.Hour))

	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"message":    "Đăng ký tài khoản thành công!",
		"token":      jwtToken,
		"user":       newUser,
		"stream_key": "",
	})
}

// Login đăng nhập tài khoản người dùng.
// POST /api/auth/login
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	limiter.InitRateLimiters()
	clientIP := limiter.GetClientIP(r)
	if limiter.LoginLimiter != nil && !limiter.LoginLimiter.Allow(clientIP) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Retry-After", "60")
		w.WriteHeader(http.StatusTooManyRequests)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error": "Quá nhiều lần thử đăng nhập từ địa chỉ này. Vui lòng thử lại sau 1 phút.",
		})
		return
	}

	limiter.LimitRequestBody(w, r, limiter.SmallJSONMaxBodyBytes)
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Dữ liệu không hợp lệ"}`, http.StatusBadRequest)
		return
	}

	req.Username = strings.ToLower(strings.TrimSpace(req.Username))
	st := h.GetStore()
	if st == nil || st.Users == nil {
		http.Error(w, `{"error":"Cơ sở dữ liệu chưa sẵn sàng"}`, http.StatusServiceUnavailable)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var user model.User
	err := st.Users.FindOne(ctx, bson.M{"username": req.Username}).Decode(&user)
	if err != nil {
		if h.RecordAccessLog != nil {
			h.RecordAccessLog(req.Username, "guest", "login_failed", clientIP, "Đăng nhập thất bại: Tài khoản không tồn tại")
		}
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "Tên đăng nhập hoặc mật khẩu không chính xác"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
		if h.RecordAccessLog != nil {
			h.RecordAccessLog(req.Username, user.Role, "login_failed", clientIP, "Đăng nhập thất bại: Sai mật khẩu")
		}
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "Tên đăng nhập hoặc mật khẩu không chính xác"})
		return
	}

	jwtToken, err := CreateToken(user, h.getSecret())
	if err != nil {
		http.Error(w, `{"error":"Lỗi tạo token"}`, http.StatusInternalServerError)
		return
	}

	token.Global().SetActiveUserToken(user.Username, jwtToken, time.Now().Add(7*24*time.Hour))

	if h.RecordAccessLog != nil {
		h.RecordAccessLog(user.Username, user.Role, "login", clientIP, fmt.Sprintf("Đăng nhập thành công với vai trò '%s'", user.Role))
	}

	streamKeyStr := ""
	publishSecretStr := ""
	var userKeys []model.StreamKey
	if user.Role == "admin" && h.EnsureAdminStreamKeys != nil {
		userKeys, err = h.EnsureAdminStreamKeys(ctx, user)
		if err != nil {
			http.Error(w, `{"error":"Không thể tải Stream Key"}`, http.StatusInternalServerError)
			return
		}
		for _, key := range userKeys {
			if key.IsActive {
				streamKeyStr = key.Key
				publishSecretStr = key.PublishSecret
				break
			}
		}
	}

	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"message":        "Đăng nhập thành công!",
		"token":          jwtToken,
		"user":           user,
		"stream_key":     streamKeyStr,
		"publish_secret": publishSecretStr,
		"stream_keys":    streamKeyCredentials(userKeys),
	})
}

// Logout thu hồi token hiện tại của người dùng.
// POST /api/auth/logout
func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	var tokenStr string
	if authHeader != "" {
		parts := strings.Split(authHeader, " ")
		if len(parts) == 2 && strings.ToLower(parts[0]) == "bearer" {
			tokenStr = parts[1]
		}
	}

	claims, err := h.getUser(r)
	username := "Ẩn danh"
	role := "guest"
	if err == nil && claims != nil {
		username = claims.Username
		role = claims.Role
		var exp time.Time
		if claims.ExpiresAt != nil {
			exp = claims.ExpiresAt.Time
		} else {
			exp = time.Now().Add(24 * time.Hour)
		}
		if tokenStr != "" {
			token.Global().RevokeToken(tokenStr, exp)
		}
	} else if tokenStr != "" {
		token.Global().RevokeToken(tokenStr, time.Now().Add(24*time.Hour))
	}

	if h.RecordAccessLog != nil {
		h.RecordAccessLog(username, role, "logout", limiter.GetClientIP(r), "Đăng xuất khỏi hệ thống và thu hồi token")
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"message": "Đã ghi nhận đăng xuất"})
}

// Me trả về thông tin tài khoản hiện tại kèm stream keys nếu là Admin.
// GET /api/auth/me
func (h *Handler) Me(w http.ResponseWriter, r *http.Request) {
	claims, err := h.getUser(r)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "Chưa đăng nhập hoặc token hết hạn"})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	objID, _ := primitive.ObjectIDFromHex(claims.UserID)
	var user model.User
	st := h.GetStore()
	if st != nil && st.Users != nil {
		_ = st.Users.FindOne(ctx, bson.M{"_id": objID}).Decode(&user)
	}

	streamKeyStr := ""
	publishSecretStr := ""
	var userKeys []model.StreamKey
	if user.Role == "admin" && h.EnsureAdminStreamKeys != nil {
		user.ID = objID
		userKeys, err = h.EnsureAdminStreamKeys(ctx, user)
		if err != nil {
			http.Error(w, `{"error":"Không thể tải Stream Key"}`, http.StatusInternalServerError)
			return
		}
		for _, key := range userKeys {
			if key.IsActive {
				streamKeyStr = key.Key
				publishSecretStr = key.PublishSecret
				break
			}
		}
	}

	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"user":           user,
		"stream_key":     streamKeyStr,
		"publish_secret": publishSecretStr,
		"stream_keys":    streamKeyCredentials(userKeys),
	})
}

// Profile xử lý xem và cập nhật thông tin cá nhân.
// GET/PUT/POST /api/auth/profile, /api/user/profile
func (h *Handler) Profile(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodGet && r.Method != http.MethodPut && r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "Method Not Allowed"})
		return
	}

	claims, err := h.getUser(r)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "Chưa đăng nhập hoặc phiên làm việc đã hết hạn"})
		return
	}

	objID, err := primitive.ObjectIDFromHex(claims.UserID)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "Mã người dùng không hợp lệ"})
		return
	}

	st := h.GetStore()
	if st == nil || st.Users == nil {
		http.Error(w, `{"error":"Cơ sở dữ liệu chưa sẵn sàng"}`, http.StatusServiceUnavailable)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	switch r.Method {
	case http.MethodGet:
		var user model.User
		if err := st.Users.FindOne(ctx, bson.M{"_id": objID}).Decode(&user); err != nil {
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Không tìm thấy thông tin tài khoản"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"user": user,
		})

	case http.MethodPut, http.MethodPost:
		limiter.LimitRequestBody(w, r, 2*1024*1024) // 2MB max

		var req struct {
			FullName        *string `json:"full_name"`
			Avatar          *string `json:"avatar"`
			Phone           *string `json:"phone"`
			CurrentPassword string  `json:"current_password"`
			NewPassword     string  `json:"new_password"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Dữ liệu gửi lên không đúng định dạng JSON"})
			return
		}

		var currentUser model.User
		if err := st.Users.FindOne(ctx, bson.M{"_id": objID}).Decode(&currentUser); err != nil {
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Không tìm thấy tài khoản người dùng"})
			return
		}

		updateFields := bson.M{}

		if req.FullName != nil {
			trimmedName := strings.TrimSpace(*req.FullName)
			if len(trimmedName) > 100 {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "Họ và tên không được vượt quá 100 ký tự"})
				return
			}
			if trimmedName != "" {
				updateFields["full_name"] = trimmedName
			}
		}

		if req.Phone != nil {
			trimmedPhone := strings.TrimSpace(*req.Phone)
			if len(trimmedPhone) > 20 {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "Số điện thoại không hợp lệ (tối đa 20 ký tự)"})
				return
			}
			updateFields["phone"] = trimmedPhone
		}

		if req.Avatar != nil {
			ava := strings.TrimSpace(*req.Avatar)
			if len(ava) > 1500000 {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "Dung lượng ảnh đại diện quá lớn (tối đa ~1MB). Vui lòng chọn ảnh nhỏ hơn."})
				return
			}
			updateFields["avatar"] = ava
		}

		if req.NewPassword != "" {
			if req.CurrentPassword == "" {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "Vui lòng nhập mật khẩu hiện tại để xác nhận đổi mật khẩu"})
				return
			}
			if err := bcrypt.CompareHashAndPassword([]byte(currentUser.Password), []byte(req.CurrentPassword)); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "Mật khẩu hiện tại không chính xác"})
				return
			}
			if len(req.NewPassword) < 6 || len(req.NewPassword) > 72 {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "Mật khẩu mới phải có độ dài từ 6 đến 72 ký tự"})
				return
			}
			hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "Lỗi mã hóa mật khẩu"})
				return
			}
			updateFields["password"] = string(hashedPassword)
		}

		if len(updateFields) == 0 {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Không có thông tin nào được cập nhật"})
			return
		}

		_, errUpdate := st.Users.UpdateOne(ctx, bson.M{"_id": objID}, bson.M{"$set": updateFields})
		if errUpdate != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Lỗi lưu dữ liệu người dùng vào cơ sở dữ liệu"})
			return
		}

		if req.FullName != nil && strings.TrimSpace(*req.FullName) != "" && currentUser.Role == "admin" && st.Keys != nil {
			_, _ = st.Keys.UpdateMany(ctx, bson.M{"user_id": objID}, bson.M{"$set": bson.M{"streamer": strings.TrimSpace(*req.FullName)}})
		}

		var updatedUser model.User
		_ = st.Users.FindOne(ctx, bson.M{"_id": objID}).Decode(&updatedUser)

		if h.RecordAccessLog != nil {
			h.RecordAccessLog(currentUser.Username, currentUser.Role, "update_profile", limiter.GetClientIP(r), "Cập nhật hồ sơ cá nhân và ảnh đại diện vào cơ sở dữ liệu")
		}

		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"message": "Cập nhật thông tin và ảnh đại diện thành công!",
			"user":    updatedUser,
		})

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "Method Not Allowed"})
	}
}

// ListUsers trả về danh sách user cho Admin / SystemAdmin xem.
// GET /api/users
func (h *Handler) ListUsers(w http.ResponseWriter, r *http.Request) {
	claims, err := h.getUser(r)
	if err != nil || (claims.Role != "admin" && claims.Role != "systemadmin") {
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "Chỉ Admin hoặc SystemAdmin mới có quyền xem"})
		return
	}

	st := h.GetStore()
	if st == nil || st.Users == nil {
		http.Error(w, `{"error":"Cơ sở dữ liệu chưa sẵn sàng"}`, http.StatusServiceUnavailable)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cursor, err := st.Users.Find(ctx, bson.M{})
	if err != nil {
		http.Error(w, `{"error":"Lỗi truy vấn users"}`, http.StatusInternalServerError)
		return
	}
	defer cursor.Close(ctx)

	var users []model.User
	_ = cursor.All(ctx, &users)
	_ = json.NewEncoder(w).Encode(users)
}

// SysadminUsers xử lý quản trị user cho SystemAdmin (xem, tạo mới, đổi role, xóa).
// GET/POST/PATCH/DELETE /api/sysadmin/users
func (h *Handler) SysadminUsers(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodGet && r.Method != http.MethodPost && r.Method != http.MethodPatch && r.Method != http.MethodDelete {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	claims, err := h.requireSystemAdmin(r)
	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	st := h.GetStore()
	if st == nil || st.Users == nil {
		http.Error(w, `{"error":"Cơ sở dữ liệu chưa sẵn sàng"}`, http.StatusServiceUnavailable)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	switch r.Method {
	case http.MethodGet:
		cursor, err := st.Users.Find(ctx, bson.M{}, options.Find().SetSort(bson.M{"created_at": -1}))
		if err != nil {
			http.Error(w, `{"error":"Lỗi truy vấn"}`, http.StatusInternalServerError)
			return
		}
		defer cursor.Close(ctx)

		var users []model.User
		_ = cursor.All(ctx, &users)

		var allKeys []model.StreamKey
		if st.Keys != nil {
			keyCursor, _ := st.Keys.Find(ctx, bson.M{})
			if keyCursor != nil {
				_ = keyCursor.All(ctx, &allKeys)
				_ = keyCursor.Close(ctx)
			}
		}

		type UserResponse struct {
			model.User
			StreamKeys []model.StreamKey `json:"stream_keys"`
		}

		var respList []UserResponse
		for _, u := range users {
			var myKeys []model.StreamKey
			for _, k := range allKeys {
				if k.UserID != nil && *k.UserID == u.ID {
					myKeys = append(myKeys, k)
				}
			}
			respList = append(respList, UserResponse{
				User:       u,
				StreamKeys: myKeys,
			})
		}

		_ = json.NewEncoder(w).Encode(respList)

	case http.MethodPost:
		limiter.LimitRequestBody(w, r, limiter.SmallJSONMaxBodyBytes)
		var req struct {
			Username  string `json:"username"`
			Password  string `json:"password"`
			FullName  string `json:"full_name"`
			Role      string `json:"role"`
			StreamKey string `json:"stream_key"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":"Dữ liệu JSON không hợp lệ"}`, http.StatusBadRequest)
			return
		}

		req.Username = strings.ToLower(strings.TrimSpace(req.Username))
		req.Password = strings.TrimSpace(req.Password)
		req.FullName = strings.TrimSpace(req.FullName)
		req.Role = strings.ToLower(strings.TrimSpace(req.Role))
		req.StreamKey = strings.ToLower(strings.TrimSpace(req.StreamKey))

		if req.Username == "" || req.Password == "" {
			http.Error(w, `{"error":"Tên đăng nhập và mật khẩu không được để trống"}`, http.StatusBadRequest)
			return
		}

		if req.Role != "admin" && req.Role != "user" {
			req.Role = "admin"
		}
		if req.FullName == "" {
			req.FullName = req.Username
		}

		var existing model.User
		if err := st.Users.FindOne(ctx, bson.M{"username": req.Username}).Decode(&existing); err == nil {
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Tên đăng nhập này đã tồn tại!"})
			return
		}

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, `{"error":"Lỗi mã hóa mật khẩu"}`, http.StatusInternalServerError)
			return
		}

		newUser := model.User{
			Username:  req.Username,
			Password:  string(hashedPassword),
			FullName:  req.FullName,
			Role:      req.Role,
			CreatedAt: time.Now(),
		}

		res, err := st.Users.InsertOne(ctx, newUser)
		if err != nil {
			http.Error(w, `{"error":"Không thể tạo tài khoản"}`, http.StatusInternalServerError)
			return
		}
		newID := res.InsertedID.(primitive.ObjectID)
		newUser.ID = newID

		var createdKey *model.StreamKey
		if req.Role == "admin" && h.InsertStreamKey != nil {
			keyVal := req.StreamKey
			if keyVal == "" && h.GenerateStreamKey != nil {
				keyVal, err = h.GenerateStreamKey()
				if err != nil {
					http.Error(w, `{"error":"Không thể tạo Stream Key an toàn"}`, http.StatusInternalServerError)
					return
				}
			}
			if st.Keys != nil {
				var existKey model.StreamKey
				if err := st.Keys.FindOne(ctx, bson.M{"key": keyVal}).Decode(&existKey); err == nil {
					keyVal = fmt.Sprintf("%s_%d", keyVal, time.Now().Unix()%1000)
				}
			}

			adminKey := model.StreamKey{
				Key:       keyVal,
				Title:     fmt.Sprintf("Kênh %s", req.FullName),
				Streamer:  req.FullName,
				UserID:    &newID,
				IsActive:  true,
				CreatedAt: time.Now(),
			}
			insertedKey, errK := h.InsertStreamKey(ctx, adminKey)
			if errK == nil {
				createdKey = &insertedKey
			}
		}

		if h.RecordAccessLog != nil {
			h.RecordAccessLog(claims.Username, claims.Role, "create_user", limiter.GetClientIP(r),
				fmt.Sprintf("Tạo tài khoản '%s' với quyền '%s'", newUser.Username, newUser.Role))
		}

		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"message":    "Tạo tài khoản thành công!",
			"user":       newUser,
			"stream_key": createdKey,
		})

	case http.MethodPatch:
		limiter.LimitRequestBody(w, r, limiter.SmallJSONMaxBodyBytes)
		var req struct {
			Username string `json:"username"`
			Role     string `json:"role"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":"Dữ liệu không hợp lệ"}`, http.StatusBadRequest)
			return
		}

		req.Username = strings.ToLower(strings.TrimSpace(req.Username))
		if req.Username == "sysadmin" {
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Không được phép thay đổi quyền của tài khoản sysadmin!"})
			return
		}

		if req.Role != "admin" && req.Role != "user" {
			http.Error(w, `{"error":"Vai trò chỉ có thể là 'admin' hoặc 'user'"}`, http.StatusBadRequest)
			return
		}

		var targetUser model.User
		err := st.Users.FindOne(ctx, bson.M{"username": req.Username}).Decode(&targetUser)
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Không tìm thấy người dùng"})
			return
		}

		_, err = st.Users.UpdateOne(ctx, bson.M{"_id": targetUser.ID}, bson.M{"$set": bson.M{"role": req.Role}})
		if err != nil {
			http.Error(w, `{"error":"Lỗi cập nhật"}`, http.StatusInternalServerError)
			return
		}

		if req.Role == "admin" && st.Keys != nil && h.InsertStreamKey != nil {
			count, _ := st.Keys.CountDocuments(ctx, bson.M{"user_id": targetUser.ID})
			if count == 0 {
				newKeyValue := ""
				if h.GenerateStreamKey != nil {
					newKeyValue, _ = h.GenerateStreamKey()
				}
				newKey := model.StreamKey{
					Key:       newKeyValue,
					Title:     fmt.Sprintf("Kênh %s", targetUser.FullName),
					Streamer:  targetUser.FullName,
					UserID:    &targetUser.ID,
					IsActive:  true,
					CreatedAt: time.Now(),
				}
				_, _ = h.InsertStreamKey(ctx, newKey)
			}
		}

		if h.RecordAccessLog != nil {
			h.RecordAccessLog(claims.Username, claims.Role, "change_role", limiter.GetClientIP(r),
				fmt.Sprintf("Đổi quyền tài khoản '%s' thành '%s'", req.Username, req.Role))
		}

		_ = json.NewEncoder(w).Encode(map[string]string{"message": "Đã cập nhật vai trò thành công!"})

	case http.MethodDelete:
		username := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("username")))
		idStr := strings.TrimSpace(r.URL.Query().Get("id"))

		filter := bson.M{}
		if idStr != "" {
			objID, err := primitive.ObjectIDFromHex(idStr)
			if err == nil {
				filter["_id"] = objID
			}
		}
		if len(filter) == 0 && username != "" {
			filter["username"] = username
		}

		if len(filter) == 0 {
			http.Error(w, `{"error":"Thiếu username hoặc id"}`, http.StatusBadRequest)
			return
		}

		var targetUser model.User
		if err := st.Users.FindOne(ctx, filter).Decode(&targetUser); err == nil {
			if targetUser.Username == "sysadmin" || targetUser.Role == "systemadmin" {
				w.WriteHeader(http.StatusForbidden)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "TUYỆT ĐỐI KHÔNG ĐƯỢC XÓA TÀI KHOẢN TỔNG QUẢN TRỊ (sysadmin)!"})
				return
			}

			if st.Keys != nil {
				_, _ = st.Keys.DeleteMany(ctx, bson.M{"user_id": targetUser.ID})
			}
			_, _ = st.Users.DeleteOne(ctx, bson.M{"_id": targetUser.ID})

			if h.RecordAccessLog != nil {
				h.RecordAccessLog(claims.Username, claims.Role, "delete_user", limiter.GetClientIP(r),
					fmt.Sprintf("Xóa tài khoản '%s' (Vai trò: %s)", targetUser.Username, targetUser.Role))
			}

			_ = json.NewEncoder(w).Encode(map[string]string{"message": "Đã xóa tài khoản và khóa luồng liên quan thành công!"})
			return
		}

		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "Không tìm thấy tài khoản"})

	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}
