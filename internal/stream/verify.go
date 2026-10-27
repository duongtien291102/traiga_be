package stream

import (
	"context"
	"crypto/subtle"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"

	"livestream-be/internal/model"
	"livestream-be/internal/store"
)

// VerifySRSWebhookSecret xác thực Secret Token cho các SRS Webhook (/auth, /auth/unpublish, /auth/dvr).
// Nếu biến môi trường SRS_WEBHOOK_SECRET được cấu hình, bắt buộc phải khớp qua Header X-SRS-Webhook-Secret hoặc query ?secret=
func VerifySRSWebhookSecret(r *http.Request) bool {
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

// VerifyStreamKey kiểm tra Stream Key hợp lệ trong MongoDB và bắt buộc chủ sở hữu phải có role == "admin".
// TÀI KHOẢN SYSTEMADMIN VÀ USER BÌNH THƯỜNG TUYỆT ĐỐI KHÔNG ĐƯỢC PHÉP LIVESTREAM.
func VerifyStreamKey(ctx context.Context, st *store.Store, streamKey, publishSecret string, matchesFunc func(secret, hash string) bool) bool {
	if st == nil || !st.IsReady() || st.Keys == nil || st.Users == nil {
		log.Printf("⛔ [AUTH BLOCKED] Không thể xác thực phòng '%s' khi cơ sở dữ liệu không sẵn sàng", streamKey)
		return false
	}

	callCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	var keyDoc model.StreamKey
	err := st.Keys.FindOne(callCtx, bson.M{"key": streamKey, "is_active": true}).Decode(&keyDoc)
	if err != nil {
		log.Printf("⛔ [AUTH BLOCKED] Phòng '%s' không tồn tại hoặc đã bị khóa", streamKey)
		return false
	}

	if matchesFunc != nil && !matchesFunc(publishSecret, keyDoc.PublishSecretHash) {
		log.Printf("⛔ [AUTH BLOCKED] Sai publish secret cho phòng '%s'", streamKey)
		return false
	}

	// YÊU CẦU: CHỈ CÓ TÀI KHOẢN CÓ ROLE LÀ ADMIN MỚI ĐƯỢC LIVESTREAM
	if keyDoc.UserID != nil {
		var u model.User
		if err := st.Users.FindOne(callCtx, bson.M{"_id": keyDoc.UserID}).Decode(&u); err == nil {
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
		var owner model.User
		ownerName := strings.ToLower(strings.TrimSpace(keyDoc.Streamer))
		ownerErr := st.Users.FindOne(callCtx, bson.M{"username": ownerName}).Decode(&owner)
		if ownerErr != nil {
			ownerErr = st.Users.FindOne(callCtx, bson.M{"full_name": keyDoc.Streamer}).Decode(&owner)
		}
		if ownerErr == nil && owner.Role == "admin" {
			log.Printf("👑 [AUTH APPROVED] Admin '%s' đang phát sóng phòng '%s'", owner.Username, streamKey)
			return true
		}
	}
	log.Printf("⛔ [AUTH BLOCKED] Phòng '%s' không thuộc tài khoản Admin nào", streamKey)
	return false
}

// VerifyInternalABRStream chỉ cho phép loopback FFmpeg publishers xuất các bản phân giải con ABR,
// và chỉ cho phòng đang hoạt động thuộc sở hữu của Admin.
func VerifyInternalABRStream(ctx context.Context, st *store.Store, app, streamKey, clientIP string) bool {
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

	if st == nil || !st.IsReady() || st.Keys == nil || st.Users == nil {
		return false
	}

	callCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	var room model.StreamKey
	if err := st.Keys.FindOne(callCtx, bson.M{"key": roomKey, "is_active": true}).Decode(&room); err != nil {
		return false
	}
	var owner model.User
	if room.UserID != nil {
		if err := st.Users.FindOne(callCtx, bson.M{"_id": room.UserID}).Decode(&owner); err != nil {
			return false
		}
	} else {
		name := strings.ToLower(strings.TrimSpace(room.Streamer))
		if err := st.Users.FindOne(callCtx, bson.M{"username": name}).Decode(&owner); err != nil {
			if err := st.Users.FindOne(callCtx, bson.M{"full_name": room.Streamer}).Decode(&owner); err != nil {
				return false
			}
		}
	}
	return owner.Role == "admin"
}
