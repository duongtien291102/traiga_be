package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"

	"livestream-be/internal/model"
)

// GenerateSecureRandomPassword tạo mật khẩu an toàn ngẫu nhiên độ dài chỉ định
func GenerateSecureRandomPassword(length int) string {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("AdminSec@%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// SeedDefaultData khởi tạo tài khoản quản trị an toàn (không dùng mật khẩu mặc định, không log mật khẩu)
func (s *Store) SeedDefaultData(ctx context.Context, recordAccessLog func(username, role, action, ip, details string)) {
	if s == nil || !s.Ready || s.Users == nil {
		return
	}

	seedCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// 1. Khởi tạo tài khoản Tổng Quản Trị Hệ Thống (sysadmin)
	var sysUser model.User
	errSys := s.Users.FindOne(seedCtx, bson.M{"username": "sysadmin"}).Decode(&sysUser)
	if errSys != nil {
		sysPass := strings.TrimSpace(os.Getenv("INITIAL_SYSADMIN_PASSWORD"))
		if sysPass == "" {
			sysPass = GenerateSecureRandomPassword(16)
			log.Printf("🛡️ [SYSADMIN BOOTSTRAP] Tài khoản 'sysadmin' đã được tạo lần đầu với mật khẩu an toàn ngẫu nhiên. Vui lòng thiết lập INITIAL_SYSADMIN_PASSWORD trong biến môi trường để chỉ định mật khẩu mong muốn.")
		} else {
			log.Printf("🛡️ [SYSADMIN BOOTSTRAP] Khởi tạo tài khoản 'sysadmin' từ biến môi trường INITIAL_SYSADMIN_PASSWORD.")
		}

		hashedPass, err := bcrypt.GenerateFromPassword([]byte(sysPass), bcrypt.DefaultCost)
		if err == nil {
			sysadmin := model.User{
				Username:  "sysadmin",
				Password:  string(hashedPass),
				FullName:  "Tổng Quản Trị Hệ Thống",
				Role:      "systemadmin",
				CreatedAt: time.Now(),
			}
			res, err := s.Users.InsertOne(seedCtx, sysadmin)
			if err == nil {
				log.Printf("🛡️ [SYSADMIN READY] Khởi tạo tài khoản System Admin thành công (ID: %s)", res.InsertedID.(primitive.ObjectID).Hex())
				if recordAccessLog != nil {
					recordAccessLog("sysadmin", "systemadmin", "init_system", "127.0.0.1", "Khởi tạo tài khoản System Admin ban đầu an toàn")
				}
			}
		}
	} else {
		log.Printf("🛡️ [SYSADMIN READY] Tài khoản System Admin 'sysadmin' đã sẵn sàng.")
	}

	// 2. Khởi tạo tài khoản admin01 (role: admin - được cấp quyền live)
	var adminUser model.User
	errAdmin := s.Users.FindOne(seedCtx, bson.M{"username": "admin01"}).Decode(&adminUser)
	if errAdmin != nil {
		adminPass := strings.TrimSpace(os.Getenv("INITIAL_ADMIN_PASSWORD"))
		if adminPass == "" {
			adminPass = GenerateSecureRandomPassword(16)
			log.Printf("👑 [ADMIN BOOTSTRAP] Tài khoản 'admin01' đã được tạo lần đầu với mật khẩu an toàn ngẫu nhiên. Vui lòng thiết lập INITIAL_ADMIN_PASSWORD trong biến môi trường để chỉ định mật khẩu mong muốn.")
		} else {
			log.Printf("👑 [ADMIN BOOTSTRAP] Khởi tạo tài khoản 'admin01' từ biến môi trường INITIAL_ADMIN_PASSWORD.")
		}

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(adminPass), bcrypt.DefaultCost)
		if err == nil {
			admin := model.User{
				Username:  "admin01",
				Password:  string(hashedPassword),
				FullName:  "Quản trị viên Streamer",
				Role:      "admin",
				CreatedAt: time.Now(),
			}
			res, err := s.Users.InsertOne(seedCtx, admin)
			if err == nil {
				log.Printf("👑 [ADMIN READY] Khởi tạo tài khoản Admin thành công (ID: %s)", res.InsertedID.(primitive.ObjectID).Hex())
			}
		}
	} else {
		log.Printf("👑 [ADMIN READY] Tài khoản Admin 'admin01' đã sẵn sàng.")
	}

	// Khởi tạo hai tài khoản chủ trại và dữ liệu danh mục trong MongoDB.
	ensureSeedAdmin := func(username, fullName, passwordEnv string) (primitive.ObjectID, bool) {
		var existing model.User
		if err := s.Users.FindOne(seedCtx, bson.M{"username": username}).Decode(&existing); err == nil {
			return existing.ID, true
		}
		password := strings.TrimSpace(os.Getenv(passwordEnv))
		if password == "" {
			password = GenerateSecureRandomPassword(16)
			log.Printf("[ADMIN BOOTSTRAP] Tài khoản '%s' tạo mật khẩu ngẫu nhiên. Đặt %s để chỉ định mật khẩu.", username, passwordEnv)
		}
		hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			log.Printf("[ADMIN BOOTSTRAP] Không thể mã hóa mật khẩu cho %s: %v", username, err)
			return primitive.NilObjectID, false
		}
		result, err := s.Users.InsertOne(seedCtx, model.User{
			Username:  username,
			Password:  string(hashed),
			FullName:  fullName,
			Role:      "admin",
			CreatedAt: time.Now(),
		})
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
		if s.Keys != nil {
			_, _ = s.Keys.UpdateOne(seedCtx, bson.M{"key": seed.key}, bson.M{"$setOnInsert": model.StreamKey{
				Key:       seed.key,
				Title:     seed.name + " — Trực Tiếp Giao Lưu Chiến Kê",
				Streamer:  seed.name,
				UserID:    &adminID,
				IsActive:  true,
				MS:        seed.ms,
				Chang:     seed.weight,
				Loi:       seed.style,
				CreatedAt: time.Now(),
			}}, options.Update().SetUpsert(true))
		}

		if s.Chickens == nil {
			continue
		}
		count, _ := s.Chickens.CountDocuments(seedCtx, bson.M{"created_by": seed.username})
		if count > 0 {
			continue
		}
		chicken := model.Chicken{
			ID:         primitive.NewObjectID(),
			MS:         seed.ms,
			Title:      seed.name + " — Chiến kê giao lưu " + seed.weight,
			Breed:      "don",
			BreedName:  "Gà Đòn Long Biên Tuyển Chọn",
			Chang:      seed.weight,
			Age:        "11 tháng tơ",
			CanVay:     "Huyền trâm đóng đúng chậu, chân vuông sừng",
			Loi:        seed.style,
			DatNuoc:    "Đã dạt 2 nước chuẩn",
			Price:      3500000,
			PriceText:  "3.500.000 đ",
			Farm:       seed.name,
			SellerName: seed.name,
			Location:   "Long Biên, Hà Nội",
			Image:      "https://images.unsplash.com/photo-1548550023-2bdb3c5beed7?q=80&w=800&auto=format&fit=crop",
			Status:     "available",
			UserID:     &adminID,
			CreatedBy:  seed.username,
			CreatedAt:  time.Now(),
			UpdatedAt:  time.Now(),
		}
		if _, err := s.Chickens.InsertOne(seedCtx, chicken); err != nil {
			log.Printf("[CHICKEN SEED] Không thể tạo dữ liệu cho %s: %v", seed.username, err)
		}
	}
}
