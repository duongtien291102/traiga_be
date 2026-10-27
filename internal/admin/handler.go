package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo/options"

	"livestream-be/internal/auth"
	"livestream-be/internal/model"
	"livestream-be/internal/store"
)

// Handler cung cấp các API quản trị cấp cao dành cho System Admin
type Handler struct {
	StoreProvider     func() *store.Store
	JWTSecretProvider func() []byte
}

// NewHandler khởi tạo admin Handler mới
func NewHandler(
	storeProvider func() *store.Store,
	jwtSecretProvider func() []byte,
) *Handler {
	return &Handler{
		StoreProvider:     storeProvider,
		JWTSecretProvider: jwtSecretProvider,
	}
}

// RequireSystemAdmin xác thực token và kiểm tra role == "systemadmin"
func (h *Handler) RequireSystemAdmin(r *http.Request) (*model.JWTClaims, error) {
	var jwtSecret []byte
	if h.JWTSecretProvider != nil {
		jwtSecret = h.JWTSecretProvider()
	}
	claims, err := auth.GetUserFromAuthHeader(r, jwtSecret)
	if err != nil {
		return nil, fmt.Errorf("chưa đăng nhập hoặc phiên làm việc hết hạn")
	}
	if claims.Role != "systemadmin" {
		return nil, fmt.Errorf("truy cập bị từ chối: Chỉ tài khoản Tổng Quản Trị (SystemAdmin) mới có quyền!")
	}
	return claims, nil
}

// Logs trả về lịch sử vào/ra và các thao tác trong hệ thống
func (h *Handler) Logs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, err := h.RequireSystemAdmin(r)
	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	st := h.StoreProvider()
	if st == nil || !st.IsReady() || st.AccessLogs == nil {
		json.NewEncoder(w).Encode([]model.AccessLog{})
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
	cursor, err := st.AccessLogs.Find(ctx, filter, opts)
	if err != nil {
		http.Error(w, `{"error":"Lỗi truy vấn logs"}`, http.StatusInternalServerError)
		return
	}
	defer cursor.Close(ctx)

	var logs []model.AccessLog
	_ = cursor.All(ctx, &logs)
	json.NewEncoder(w).Encode(logs)
}

// LiveStats trả về thống kê tổng hợp giờ live, tần suất và danh sách phiên live
func (h *Handler) LiveStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, err := h.RequireSystemAdmin(r)
	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	st := h.StoreProvider()
	if st == nil || !st.IsReady() || st.Sessions == nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"total_sessions":         0,
			"total_duration_seconds": 0,
			"active_sessions":        0,
			"total_users":            0,
			"total_admins":           0,
			"streamer_stats":         []interface{}{},
			"daily_stats":            []interface{}{},
			"sessions":               []interface{}{},
		})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 1. Lấy tất cả phiên live gần nhất
	opts := options.Find().SetSort(bson.M{"started_at": -1}).SetLimit(200)
	cursor, err := st.Sessions.Find(ctx, bson.M{}, opts)
	if err != nil {
		http.Error(w, `{"error":"Lỗi truy vấn"}`, http.StatusInternalServerError)
		return
	}
	defer cursor.Close(ctx)

	var allSessions []model.LiveSession
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
	var userCount, adminCount int64
	if st.Users != nil {
		userCount, _ = st.Users.CountDocuments(ctx, bson.M{})
		adminCount, _ = st.Users.CountDocuments(ctx, bson.M{"role": "admin"})
	}

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
