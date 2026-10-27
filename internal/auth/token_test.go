package auth

import (
	"net/http/httptest"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"

	"livestream-be/internal/model"
	"livestream-be/internal/security/token"
)

func TestToken_CreateAndExtract(t *testing.T) {
	secret := []byte("super-secret-jwt-key-at-least-32-chars-long!")
	user := model.User{
		ID:       primitive.NewObjectID(),
		Username: "testuser",
		Role:     "admin",
	}

	tok, err := CreateToken(user, secret)
	if err != nil {
		t.Fatalf("failed to create token: %v", err)
	}

	req := httptest.NewRequest("GET", "/api/test", nil)
	req.Header.Set("Authorization", "Bearer "+tok)

	claims, err := GetUserFromAuthHeader(req, secret)
	if err != nil {
		t.Fatalf("failed to get user from auth header: %v", err)
	}

	if claims.Username != "testuser" || claims.Role != "admin" {
		t.Fatalf("claims mismatch: got username=%s role=%s", claims.Username, claims.Role)
	}

	// Test revoked token
	token.Global().RevokeToken(tok, time.Now().Add(1*time.Hour))
	_, errRevoked := GetUserFromAuthHeader(req, secret)
	if errRevoked == nil {
		t.Fatalf("expected error for revoked token, got nil")
	}
}

func TestValidUsernameRegex(t *testing.T) {
	valid := []string{"admin01", "user.name", "user_123", "abc-def"}
	for _, u := range valid {
		if !ValidUsernameRegex.MatchString(u) {
			t.Errorf("expected %q to be valid username", u)
		}
	}

	invalid := []string{"ab", "user name", "User123", "a!@#", "very-very-long-username-exceeding-thirty-two-chars"}
	for _, u := range invalid {
		if ValidUsernameRegex.MatchString(u) {
			t.Errorf("expected %q to be invalid username", u)
		}
	}
}
