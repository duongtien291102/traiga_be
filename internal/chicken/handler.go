package chicken

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/options"

	"livestream-be/internal/model"
	"livestream-be/internal/security/limiter"
	"livestream-be/internal/store"
)

// Handler handles Chợ Gà (chicken market) operations.
type Handler struct {
	GetStore        func() *store.Store
	GetUser         func(r *http.Request) (*model.JWTClaims, error)
	RecordAccessLog func(username, role, action, ip, details string)
}

// NewHandler creates a new chicken market handler with the provided dependencies.
func NewHandler(
	getStore func() *store.Store,
	getUser func(r *http.Request) (*model.JWTClaims, error),
	recordAccessLog func(username, role, action, ip, details string),
) *Handler {
	return &Handler{
		GetStore:        getStore,
		GetUser:         getUser,
		RecordAccessLog: recordAccessLog,
	}
}

// ServeHTTP handles /api/chickens requests (GET, POST, DELETE, PATCH).
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		var st *store.Store
		if h.GetStore != nil {
			st = h.GetStore()
		}

		if st == nil || !st.IsReady() || st.Chickens == nil {
			_ = json.NewEncoder(w).Encode([]model.Chicken{})
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		filter := bson.M{}
		if breed := strings.TrimSpace(r.URL.Query().Get("breed")); breed != "" && breed != "all" {
			filter["breed"] = breed
		}
		if status := strings.TrimSpace(r.URL.Query().Get("status")); status != "" && status != "all" {
			filter["status"] = status
		}

		opts := options.Find().SetSort(bson.M{"created_at": -1}).SetLimit(100)
		cursor, err := st.Chickens.Find(ctx, filter, opts)
		if err != nil {
			_ = json.NewEncoder(w).Encode([]model.Chicken{})
			return
		}
		defer cursor.Close(ctx)

		var list []model.Chicken
		if err := cursor.All(ctx, &list); err != nil {
			_ = json.NewEncoder(w).Encode([]model.Chicken{})
			return
		}
		if list == nil {
			list = []model.Chicken{}
		}
		_ = json.NewEncoder(w).Encode(list)

	case http.MethodPost:
		if h.GetUser == nil {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Yêu cầu đăng nhập để đăng bán gà"})
			return
		}

		claims, err := h.GetUser(r)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Yêu cầu đăng nhập để đăng bán gà"})
			return
		}
		if claims.Role != "admin" && claims.Role != "systemadmin" {
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Chỉ tài khoản Quản trị viên (Admin) mới có quyền đăng bán gà"})
			return
		}

		limiter.LimitRequestBody(w, r, limiter.SmallJSONMaxBodyBytes)
		var item model.Chicken
		if err := json.NewDecoder(r.Body).Decode(&item); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Dữ liệu JSON không hợp lệ"})
			return
		}

		item.Title = strings.TrimSpace(item.Title)
		if item.Title == "" {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Tiêu đề chiến kê không được để trống"})
			return
		}

		now := time.Now()
		item.ID = primitive.NewObjectID()
		if item.MS == "" {
			item.MS = "MS " + item.ID.Hex()[len(item.ID.Hex())-4:]
		}
		if item.Status == "" {
			item.Status = "available"
		}
		if objID, errID := primitive.ObjectIDFromHex(claims.UserID); errID == nil {
			item.UserID = &objID
		}
		item.CreatedBy = claims.Username
		item.CreatedAt = now
		item.UpdatedAt = now

		var st *store.Store
		if h.GetStore != nil {
			st = h.GetStore()
		}
		if st == nil || st.Chickens == nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Cơ sở dữ liệu chưa sẵn sàng"})
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		_, errInsert := st.Chickens.InsertOne(ctx, item)
		if errInsert != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Không thể lưu chiến kê vào cơ sở dữ liệu"})
			return
		}

		if h.RecordAccessLog != nil {
			h.RecordAccessLog(claims.Username, claims.Role, "post_chicken", limiter.GetClientIP(r), "Đăng bán chiến kê: "+item.Title)
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(item)

	case http.MethodDelete:
		if h.GetUser == nil {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Yêu cầu đăng nhập"})
			return
		}

		claims, err := h.GetUser(r)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Yêu cầu đăng nhập"})
			return
		}
		if claims.Role != "admin" && claims.Role != "systemadmin" {
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Không có quyền thực hiện thao tác này"})
			return
		}

		idStr := strings.TrimSpace(r.URL.Query().Get("id"))
		if idStr == "" {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Thiếu tham số id"})
			return
		}

		objID, errID := primitive.ObjectIDFromHex(idStr)
		if errID != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "ID không hợp lệ"})
			return
		}

		var st *store.Store
		if h.GetStore != nil {
			st = h.GetStore()
		}
		if st == nil || st.Chickens == nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Cơ sở dữ liệu chưa sẵn sàng"})
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		filter := bson.M{"_id": objID}
		if claims.Role != "systemadmin" {
			if callerID, errCaller := primitive.ObjectIDFromHex(claims.UserID); errCaller == nil {
				filter["user_id"] = callerID
			} else {
				filter["created_by"] = claims.Username
			}
		}

		res, errDel := st.Chickens.DeleteOne(ctx, filter)
		if errDel != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Không thể xóa chiến kê"})
			return
		}
		if res.DeletedCount == 0 {
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Không tìm thấy chiến kê hoặc bạn không có quyền xóa"})
			return
		}

		if h.RecordAccessLog != nil {
			h.RecordAccessLog(claims.Username, claims.Role, "delete_chicken", limiter.GetClientIP(r), "Xóa chiến kê ID: "+idStr)
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "deleted_id": idStr})

	case http.MethodPatch:
		if h.GetUser == nil {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Yêu cầu đăng nhập"})
			return
		}

		claims, err := h.GetUser(r)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Yêu cầu đăng nhập"})
			return
		}
		if claims.Role != "admin" && claims.Role != "systemadmin" {
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Không có quyền thực hiện"})
			return
		}

		limiter.LimitRequestBody(w, r, limiter.SmallJSONMaxBodyBytes)
		var payload struct {
			ID     string `json:"id"`
			Status string `json:"status"` // "available", "sold"
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Dữ liệu JSON không hợp lệ"})
			return
		}

		objID, errID := primitive.ObjectIDFromHex(payload.ID)
		if errID != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "ID không hợp lệ"})
			return
		}

		var st *store.Store
		if h.GetStore != nil {
			st = h.GetStore()
		}
		if st == nil || st.Chickens == nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Cơ sở dữ liệu chưa sẵn sàng"})
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		filter := bson.M{"_id": objID}
		if claims.Role != "systemadmin" {
			if callerID, errCaller := primitive.ObjectIDFromHex(claims.UserID); errCaller == nil {
				filter["user_id"] = callerID
			} else {
				filter["created_by"] = claims.Username
			}
		}

		update := bson.M{
			"$set": bson.M{
				"status":     payload.Status,
				"updated_at": time.Now(),
			},
		}

		res, errUp := st.Chickens.UpdateOne(ctx, filter, update)
		if errUp != nil || res.MatchedCount == 0 {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Không thể cập nhật hoặc không có quyền"})
			return
		}

		_ = json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "status": payload.Status})

	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}
