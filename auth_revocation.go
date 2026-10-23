package main

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"sync"
	"time"
)

// TokenRevocationStore quản lý danh sách token đã bị thu hồi (đăng xuất hoặc đăng nhập thiết bị mới) trong bộ nhớ
type TokenRevocationStore struct {
	mu               sync.RWMutex
	revokedHashes    map[string]time.Time // sha256(token) -> expiresAt
	activeUserTokens map[string]string    // username -> sha256(activeToken)
}

var globalTokenRevocationStore = &TokenRevocationStore{
	revokedHashes:    make(map[string]time.Time),
	activeUserTokens: make(map[string]string),
}

func init() {
	// Goroutine dọn dẹp các token đã hết hạn tự nhiên để giải phóng RAM
	go func() {
		ticker := time.NewTicker(3 * time.Minute)
		for range ticker.C {
			globalTokenRevocationStore.cleanup()
		}
	}()
}

// hashToken tính mã băm SHA-256 của token để tiết kiệm bộ nhớ và không lưu token thô
func hashToken(tokenStr string) string {
	clean := strings.TrimSpace(tokenStr)
	clean = strings.TrimPrefix(clean, "Bearer ")
	clean = strings.TrimPrefix(clean, "bearer ")
	h := sha256.Sum256([]byte(clean))
	return hex.EncodeToString(h[:])
}

// RevokeToken đưa một JWT token vào danh sách đen thu hồi cho đến khi token tự hết hạn
func (s *TokenRevocationStore) RevokeToken(tokenStr string, expiresAt time.Time) {
	if tokenStr == "" {
		return
	}
	hash := hashToken(tokenStr)

	// Nếu expiresAt không xác định hoặc trong quá khứ, giữ tối thiểu 24h
	if expiresAt.Before(time.Now()) {
		expiresAt = time.Now().Add(24 * time.Hour)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.revokedHashes[hash] = expiresAt
}

// IsTokenRevoked kiểm tra xem token đã bị thu hồi do người dùng đăng xuất hay chưa
func (s *TokenRevocationStore) IsTokenRevoked(tokenStr string) bool {
	if tokenStr == "" {
		return false
	}
	hash := hashToken(tokenStr)

	s.mu.RLock()
	expiresAt, exists := s.revokedHashes[hash]
	s.mu.RUnlock()

	if !exists {
		return false
	}

	// Nếu token đã hết hạn tự nhiên, coi như đã hết hạn / thu hồi
	if time.Now().After(expiresAt) {
		s.mu.Lock()
		delete(s.revokedHashes, hash)
		s.mu.Unlock()
	}

	return true
}

// SetActiveUserToken ghi nhận token mới nhất của user và tự động thu hồi token cũ (chỉ cho phép 1 thiết bị đăng nhập cùng lúc)
func (s *TokenRevocationStore) SetActiveUserToken(username, tokenStr string, expiresAt time.Time) {
	userKey := strings.ToLower(strings.TrimSpace(username))
	if userKey == "" || tokenStr == "" {
		return
	}
	newHash := hashToken(tokenStr)
	if expiresAt.Before(time.Now()) {
		expiresAt = time.Now().Add(7 * 24 * time.Hour)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if oldHash, exists := s.activeUserTokens[userKey]; exists && oldHash != "" && oldHash != newHash {
		s.revokedHashes[oldHash] = expiresAt
	}
	s.activeUserTokens[userKey] = newHash
}

// Reset xóa toàn bộ danh sách thu hồi (hữu ích cho unit test)
func (s *TokenRevocationStore) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revokedHashes = make(map[string]time.Time)
	s.activeUserTokens = make(map[string]string)
}

// cleanup dọn dẹp các token đã hết hạn
func (s *TokenRevocationStore) cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for hash, exp := range s.revokedHashes {
		if now.After(exp) {
			delete(s.revokedHashes, hash)
		}
	}
}
