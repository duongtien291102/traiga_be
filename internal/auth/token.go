package auth

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"livestream-be/internal/model"
	"livestream-be/internal/security/token"
)

// ValidUsernameRegex kiểm tra username từ 3 đến 32 ký tự hợp lệ.
var ValidUsernameRegex = regexp.MustCompile(`^[a-z0-9_.-]{3,32}$`)

// CreateToken sinh chuỗi JWT token cho người dùng (thời hạn 7 ngày).
func CreateToken(user model.User, secret []byte) (string, error) {
	claims := model.JWTClaims{
		UserID:   user.ID.Hex(),
		Username: user.Username,
		Role:     user.Role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(7 * 24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return t.SignedString(secret)
}

// GetUserFromAuthHeader trích xuất thông tin user từ Header Authorization.
func GetUserFromAuthHeader(r *http.Request, secret []byte) (*model.JWTClaims, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return nil, fmt.Errorf("missing Authorization header")
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return nil, fmt.Errorf("invalid Authorization format")
	}

	tokenStr := parts[1]
	if token.Global().IsTokenRevoked(tokenStr) {
		return nil, fmt.Errorf("token has been revoked")
	}

	t, err := jwt.ParseWithClaims(tokenStr, &model.JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return secret, nil
	})

	if err != nil || !t.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	claims, ok := t.Claims.(*model.JWTClaims)
	if !ok {
		return nil, fmt.Errorf("cannot parse claims")
	}

	return claims, nil
}
