package model

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// User đại diện cho tài khoản người dùng trong MongoDB
type User struct {
	ID        primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	Username  string             `bson:"username" json:"username"`
	Password  string             `bson:"password" json:"-"`
	FullName  string             `bson:"full_name" json:"full_name"`
	Avatar    string             `bson:"avatar,omitempty" json:"avatar,omitempty"`
	Phone     string             `bson:"phone,omitempty" json:"phone,omitempty"`
	Role      string             `bson:"role" json:"role"` // "systemadmin", "admin" hoặc "user"
	CreatedAt time.Time          `bson:"created_at" json:"created_at"`
}

// JWTClaims cấu trúc payload trong JWT token
type JWTClaims struct {
	UserID   string `json:"user_id"`
	Username string `json:"username"`
	Role     string `json:"role"`
	jwt.RegisteredClaims
}
