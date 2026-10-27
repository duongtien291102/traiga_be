package main

import (
	"net/http"

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
	streamHandler.PublicRooms(w, r)
}
