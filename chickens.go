package main

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo/options"

	"livestream-be/internal/chicken"
	"livestream-be/internal/model"
	"livestream-be/internal/store"
)

// Type aliases for gradual refactoring (Phase 2)
type Chicken = model.Chicken

var chickenHandler = chicken.NewHandler(
	func() *store.Store { return globalStore },
	getUserFromAuthHeader,
	recordAccessLog,
)

// apiChickensHandler xử lý CRUD gà đăng bán trong Chợ Gà (kết nối MongoDB thật 100%)
func apiChickensHandler(w http.ResponseWriter, r *http.Request) {
	chickenHandler.ServeHTTP(w, r)
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
