package main

import (
	"encoding/json"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// clientBucket lưu trạng thái rate limit của một client IP
type clientBucket struct {
	tokens     float64
	lastUpdate time.Time
	lastSeen   time.Time
}

// IPRateLimiter giới hạn tần suất request theo IP sử dụng thuật toán Token Bucket
type IPRateLimiter struct {
	mu         sync.Mutex
	clients    map[string]*clientBucket
	rate       float64       // số token nạp lại mỗi giây
	capacity   float64       // dung lượng tối đa (burst)
	cleanupTTL time.Duration // thời gian giữ bản ghi không hoạt động trước khi giải phóng bộ nhớ
}

// NewIPRateLimiter khởi tạo một Rate Limiter với cấu hình rate và capacity
func NewIPRateLimiter(rate float64, capacity float64, cleanupTTL time.Duration) *IPRateLimiter {
	limiter := &IPRateLimiter{
		clients:    make(map[string]*clientBucket),
		rate:       rate,
		capacity:   capacity,
		cleanupTTL: cleanupTTL,
	}

	// Goroutine định kỳ dọn dẹp các IP đã hết hạn để tránh rò rỉ bộ nhớ (unbounded map)
	go func() {
		ticker := time.NewTicker(cleanupTTL / 2)
		for range ticker.C {
			limiter.cleanup()
		}
	}()

	return limiter
}

// Allow kiểm tra xem IP có được phép thực hiện request tiếp theo hay không
func (l *IPRateLimiter) Allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	bucket, exists := l.clients[ip]
	if !exists {
		// Tạo bucket mới cho client
		l.clients[ip] = &clientBucket{
			tokens:     l.capacity - 1, // tiêu tốn 1 token cho request đầu tiên
			lastUpdate: now,
			lastSeen:   now,
		}
		return true
	}

	bucket.lastSeen = now

	// Tính lượng token được hồi phục theo thời gian trôi qua
	elapsed := now.Sub(bucket.lastUpdate).Seconds()
	bucket.tokens += elapsed * l.rate
	if bucket.tokens > l.capacity {
		bucket.tokens = l.capacity
	}
	bucket.lastUpdate = now

	// Kiểm tra xem còn đủ token không
	if bucket.tokens >= 1.0 {
		bucket.tokens -= 1.0
		return true
	}

	return false
}

// Reset xóa rate limit của một IP (hữu ích cho unit test)
func (l *IPRateLimiter) Reset(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.clients, ip)
}

// cleanup dọn dẹp các IP không còn hoạt động để giới hạn bộ nhớ
func (l *IPRateLimiter) cleanup() {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	for ip, bucket := range l.clients {
		if now.Sub(bucket.lastSeen) > l.cleanupTTL {
			delete(l.clients, ip)
		}
	}
}

// getClientIP trích xuất địa chỉ IP thực tế của client một cách an toàn.
// Tuyệt đối không tin cậy X-Forwarded-For trừ khi biến TRUST_PROXY=true được cấu hình từ proxy nội bộ đáng tin cậy.
func getClientIP(r *http.Request) string {
	if os.Getenv("TRUST_PROXY") == "true" {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			clientIP := strings.TrimSpace(parts[0])
			if clientIP != "" {
				return clientIP
			}
		}
		if xri := r.Header.Get("X-Real-IP"); xri != "" {
			return strings.TrimSpace(xri)
		}
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return strings.TrimSpace(r.RemoteAddr)
	}
	return host
}

// Global rate limiters
var (
	loginLimiter *IPRateLimiter
	limiterOnce  sync.Once
)

// initRateLimiters khởi tạo các limiter từ biến môi trường
func initRateLimiters() {
	limiterOnce.Do(func() {
		// Mặc định cho login: 5 lần thử / phút (rate = 5/60 req/s, capacity = 5)
		maxAttempts := 5.0
		if val := os.Getenv("LOGIN_RATE_LIMIT_MAX"); val != "" {
			if v, err := strconv.ParseFloat(val, 64); err == nil && v > 0 {
				maxAttempts = v
			}
		}

		windowSeconds := 60.0
		if val := os.Getenv("LOGIN_RATE_LIMIT_WINDOW_SECS"); val != "" {
			if v, err := strconv.ParseFloat(val, 64); err == nil && v > 0 {
				windowSeconds = v
			}
		}

		rate := maxAttempts / windowSeconds
		loginLimiter = NewIPRateLimiter(rate, maxAttempts, 5*time.Minute)
	})
}

// RateLimitLoginMiddleware bọc handler đăng nhập và chặn brute force attack
func RateLimitLoginMiddleware(next http.HandlerFunc) http.HandlerFunc {
	initRateLimiters()
	return func(w http.ResponseWriter, r *http.Request) {
		clientIP := getClientIP(r)
		if !loginLimiter.Allow(clientIP) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", "60")
			w.WriteHeader(http.StatusTooManyRequests)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error": "Quá nhiều lần thử đăng nhập từ địa chỉ này. Vui lòng thử lại sau 1 phút.",
			})
			return
		}

		next(w, r)
	}
}

// TokenBucket dùng để giới hạn tốc độ message trên từng WebSocket connection
type TokenBucket struct {
	mu         sync.Mutex
	tokens     float64
	capacity   float64
	rate       float64
	lastUpdate time.Time
}

// NewTokenBucket tạo bucket mới cho 1 socket connection
func NewTokenBucket(rate float64, capacity float64) *TokenBucket {
	return &TokenBucket{
		tokens:     capacity,
		capacity:   capacity,
		rate:       rate,
		lastUpdate: time.Now(),
	}
}

// Allow kiểm tra xem socket có được phép gửi message tiếp theo không
func (tb *TokenBucket) Allow() bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(tb.lastUpdate).Seconds()
	tb.tokens += elapsed * tb.rate
	if tb.tokens > tb.capacity {
		tb.tokens = tb.capacity
	}
	tb.lastUpdate = now

	if tb.tokens >= 1.0 {
		tb.tokens -= 1.0
		return true
	}
	return false
}
