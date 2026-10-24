package main

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// Chicken đại diện cho 1 chiến kê đăng bán trên Chợ Gà Ba Miền lưu trong MongoDB
type Chicken struct {
	ID         primitive.ObjectID  `bson:"_id,omitempty" json:"id"`
	MS         string              `bson:"ms" json:"ms"`
	Title      string              `bson:"title" json:"title"`
	Breed      string              `bson:"breed" json:"breed"`
	BreedName  string              `bson:"breed_name" json:"breedName"`
	Chang      string              `bson:"chang" json:"chang"`
	Age        string              `bson:"age" json:"age"`
	CanVay     string              `bson:"can_vay" json:"canVay"`
	Loi        string              `bson:"loi" json:"loi"`
	DatNuoc    string              `bson:"dat_nuoc" json:"datNuoc"`
	Price      int64               `bson:"price" json:"price"`
	PriceText  string              `bson:"price_text" json:"priceText"`
	Farm       string              `bson:"farm" json:"farm"`
	SellerName string              `bson:"seller_name" json:"sellerName"`
	Phone      string              `bson:"phone" json:"phone"`
	Zalo       string              `bson:"zalo" json:"zalo"`
	Location   string              `bson:"location" json:"location"`
	Image      string              `bson:"image" json:"image"`
	VideoURL   string              `bson:"video_url,omitempty" json:"videoUrl,omitempty"`
	Note       string              `bson:"note,omitempty" json:"note,omitempty"`
	Status     string              `bson:"status" json:"status"` // "available", "sold"
	UserID     *primitive.ObjectID `bson:"user_id,omitempty" json:"userId,omitempty"`
	CreatedBy  string              `bson:"created_by,omitempty" json:"createdBy,omitempty"`
	CreatedAt  time.Time           `bson:"created_at" json:"createdAt"`
	UpdatedAt  time.Time           `bson:"updated_at" json:"updatedAt"`
}

// apiChickensHandler xử lý CRUD gà đăng bán trong Chợ Gà (kết nối MongoDB thật 100%)
func apiChickensHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		// Public: Xem danh sách gà đăng bán thực tế từ MongoDB
		mongoMutex.RLock()
		coll := chickensColl
		ready := isMongoReady
		mongoMutex.RUnlock()

		if !ready || coll == nil {
			json.NewEncoder(w).Encode([]Chicken{})
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
		cursor, err := coll.Find(ctx, filter, opts)
		if err != nil {
			json.NewEncoder(w).Encode([]Chicken{})
			return
		}
		defer cursor.Close(ctx)

		var list []Chicken
		if err := cursor.All(ctx, &list); err != nil {
			json.NewEncoder(w).Encode([]Chicken{})
			return
		}
		if list == nil {
			list = []Chicken{}
		}
		json.NewEncoder(w).Encode(list)

	case http.MethodPost:
		// Chỉ Admin và SystemAdmin mới được quyền đăng bán gà
		claims, err := getUserFromAuthHeader(r)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "Yêu cầu đăng nhập để đăng bán gà"})
			return
		}
		if claims.Role != "admin" && claims.Role != "systemadmin" {
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{"error": "Chỉ tài khoản Quản trị viên (Admin) mới có quyền đăng bán gà"})
			return
		}

		limitRequestBody(w, r, SmallJSONMaxBodyBytes)
		var item Chicken
		if err := json.NewDecoder(r.Body).Decode(&item); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "Dữ liệu JSON không hợp lệ"})
			return
		}

		item.Title = strings.TrimSpace(item.Title)
		if item.Title == "" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "Tiêu đề chiến kê không được để trống"})
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

		mongoMutex.RLock()
		coll := chickensColl
		mongoMutex.RUnlock()

		if coll == nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			json.NewEncoder(w).Encode(map[string]string{"error": "Cơ sở dữ liệu chưa sẵn sàng"})
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		_, errInsert := coll.InsertOne(ctx, item)
		if errInsert != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "Không thể lưu chiến kê vào cơ sở dữ liệu"})
			return
		}

		recordAccessLog(claims.Username, claims.Role, "post_chicken", getClientIP(r), "Đăng bán chiến kê: "+item.Title)
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(item)

	case http.MethodDelete:
		// Xóa gà: Admin chỉ xóa gà do mình đăng, SystemAdmin xóa tất cả (chống IDOR)
		claims, err := getUserFromAuthHeader(r)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "Yêu cầu đăng nhập"})
			return
		}
		if claims.Role != "admin" && claims.Role != "systemadmin" {
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{"error": "Không có quyền thực hiện thao tác này"})
			return
		}

		idStr := strings.TrimSpace(r.URL.Query().Get("id"))
		if idStr == "" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "Thiếu tham số id"})
			return
		}

		objID, errID := primitive.ObjectIDFromHex(idStr)
		if errID != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "ID không hợp lệ"})
			return
		}

		mongoMutex.RLock()
		coll := chickensColl
		mongoMutex.RUnlock()

		if coll == nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			json.NewEncoder(w).Encode(map[string]string{"error": "Cơ sở dữ liệu chưa sẵn sàng"})
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

		res, errDel := coll.DeleteOne(ctx, filter)
		if errDel != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "Không thể xóa chiến kê"})
			return
		}
		if res.DeletedCount == 0 {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"error": "Không tìm thấy chiến kê hoặc bạn không có quyền xóa"})
			return
		}

		recordAccessLog(claims.Username, claims.Role, "delete_chicken", getClientIP(r), "Xóa chiến kê ID: "+idStr)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "deleted_id": idStr})

	case http.MethodPatch:
		// Cập nhật trạng thái gà (Đã bán / Còn bán)
		claims, err := getUserFromAuthHeader(r)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "Yêu cầu đăng nhập"})
			return
		}
		if claims.Role != "admin" && claims.Role != "systemadmin" {
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{"error": "Không có quyền thực hiện"})
			return
		}

		limitRequestBody(w, r, SmallJSONMaxBodyBytes)
		var payload struct {
			ID     string `json:"id"`
			Status string `json:"status"` // "available", "sold"
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "Dữ liệu JSON không hợp lệ"})
			return
		}

		objID, errID := primitive.ObjectIDFromHex(payload.ID)
		if errID != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "ID không hợp lệ"})
			return
		}

		mongoMutex.RLock()
		coll := chickensColl
		mongoMutex.RUnlock()

		if coll == nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			json.NewEncoder(w).Encode(map[string]string{"error": "Cơ sở dữ liệu chưa sẵn sàng"})
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

		res, errUp := coll.UpdateOne(ctx, filter, update)
		if errUp != nil || res.MatchedCount == 0 {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "Không thể cập nhật hoặc không có quyền"})
			return
		}

		json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "status": payload.Status})

	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

// apiPublicRoomsHandler trả về danh sách các phòng live công khai cho người xem trên web từ MongoDB
// GET /api/rooms hoặc GET /api/public/rooms
func apiPublicRoomsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	mongoMutex.RLock()
	coll := keysColl
	sessColl := sessionsColl
	ready := isMongoReady
	mongoMutex.RUnlock()

	if !ready || coll == nil {
		json.NewEncoder(w).Encode([]interface{}{})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cursor, err := coll.Find(ctx, bson.M{"is_active": true}, options.Find().SetSort(bson.M{"created_at": 1}))
	if err != nil {
		json.NewEncoder(w).Encode([]interface{}{})
		return
	}
	defer cursor.Close(ctx)

	var keys []StreamKey
	_ = cursor.All(ctx, &keys)

	type PublicRoomInfo struct {
		ID       string `json:"id"`
		Key      string `json:"key"`
		Title    string `json:"title"`
		Farm     string `json:"farm"`
		Streamer string `json:"streamer"`
		MS       string `json:"ms"`
		Chang    string `json:"chang"`
		Loi      string `json:"loi"`
		CanVay   string `json:"can_vay"`
		DatNuoc  string `json:"dat_nuoc"`
		Thumb    string `json:"thumb"`
		IsLive   bool   `json:"is_live"`
		Viewers  int    `json:"viewers"`
	}

	result := make([]PublicRoomInfo, 0, len(keys))
	for _, k := range keys {
		isLive := false
		if sessColl != nil {
			var sess LiveSession
			if errSess := sessColl.FindOne(ctx, bson.M{"stream_key": k.Key, "status": "live"}).Decode(&sess); errSess == nil {
				isLive = true
			}
		}

		viewers := 0
		if globalChatHub != nil {
			globalChatHub.mutex.RLock()
			if clients, ok := globalChatHub.rooms[k.Key]; ok {
				viewers = len(clients)
			}
			globalChatHub.mutex.RUnlock()
		}

		farmName := k.Streamer
		if !strings.HasPrefix(farmName, "Trại") {
			farmName = "Trại Gà " + farmName
		}
		if !strings.Contains(farmName, "Thành Trung") {
			farmName = "Trại Gà Thành Trung 01"
		}

		result = append(result, PublicRoomInfo{
			ID:       k.Key,
			Key:      k.Key,
			Title:    k.Title,
			Farm:     farmName,
			Streamer: k.Streamer,
			MS:       k.MS,
			Chang:    k.Chang,
			Loi:      k.Loi,
			CanVay:   k.CanVay,
			DatNuoc:  k.DatNuoc,
			Thumb:    k.Thumb,
			IsLive:   isLive,
			Viewers:  viewers,
		})
	}

	json.NewEncoder(w).Encode(result)
}
