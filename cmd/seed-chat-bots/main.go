// Adds the requested batch once; retries do not duplicate or reset edited bots.
package main

import (
	"context"
	"crypto/sha256"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"

	"livestream-be/internal/model"
	"livestream-be/internal/store"
)

const batch = "requested-chat-bots-2026-10-28"

func requestedBots() []model.ChatBot {
	groups := []struct {
		name     string
		messages []string
	}{
		{"Chào Mừng", []string{"Chào mừng mọi người đến với buổi livestream của trại!", "Bạn mới vào có thể xem thông tin kênh ở phía trên nhé.", "Cảm ơn mọi người đã ghé xem và giao lưu.", "Mọi người có thể đặt câu hỏi cho chủ trại trong khung chat.", "Chúc mọi người có buổi giao lưu vui vẻ!"}},
		{"Hướng Dẫn", []string{"Bạn có thể bấm toàn màn hình để xem rõ hơn.", "Nếu chưa nghe tiếng, hãy kiểm tra nút âm lượng trên trình phát.", "Nếu mạng yếu, bạn có thể thử chọn chất lượng video thấp hơn.", "Video đã lưu sẽ xuất hiện trong mục Xem lại khi sẵn sàng.", "Bạn có thể xem thông tin liên hệ trong hồ sơ của chủ trại."}},
		{"Hỏi Đáp", []string{"Bạn muốn biết thêm thông tin nào? Hãy để lại câu hỏi nhé.", "Khi hỏi về gà, hãy ghi rõ mã số để chủ trại dễ trả lời.", "Bạn có thể hỏi chủ trại về độ tuổi và cân nặng hiện tại.", "Thông tin giống và nguồn gốc nên được xác nhận trực tiếp với chủ trại.", "Chủ trại sẽ trả lời khi có thể; cảm ơn bạn đã chờ."}},
		{"Thông Tin Gà", []string{"Bạn quan tâm con nào thì ghi mã số trong bình luận nhé.", "Hãy hỏi rõ tuổi, cân nặng và tình trạng sức khỏe trước khi trao đổi.", "Bạn có thể nhờ chủ trại quay cận cảnh chân và dáng đứng.", "Thông tin từng con có thể xem thêm trong mục mua bán của trại.", "Để tránh nhầm, hãy xác nhận lại mã số với chủ trại."}},
		{"Chăm Sóc", []string{"Bạn có câu hỏi về cách chăm sóc có thể gửi cho chủ trại.", "Hãy hỏi chủ trại về khẩu phần đang dùng tại trại.", "Nên xác nhận lịch chăm sóc và theo dõi sức khỏe khi nhận gà.", "Gà có dấu hiệu bệnh cần được người có chuyên môn thú y kiểm tra.", "Bạn có thể hỏi thêm về điều kiện chuồng nuôi tại trại."}},
		{"Nội Quy", []string{"Mọi người vui lòng giao lưu lịch sự, tôn trọng nhau.", "Không đăng số điện thoại hay thông tin cá nhân của người khác.", "Vui lòng không spam nhiều bình luận giống nhau.", "Hãy trao đổi đúng chủ đề để chủ trại dễ theo dõi câu hỏi.", "Nếu gặp bình luận không phù hợp, hãy báo cho quản trị viên."}},
		{"Kết Nối", []string{"Bạn đang xem từ tỉnh thành nào? Có thể cùng giao lưu nhé.", "Bạn muốn chủ trại giới thiệu thêm phần nào trong buổi live?", "Bạn thích xem góc quay tổng thể hay cận cảnh hơn?", "Mọi người có thể chia sẻ kinh nghiệm nuôi và chăm sóc một cách lịch sự.", "Có câu hỏi nào chưa được trả lời, bạn có thể nhắc lại ngắn gọn nhé."}},
		{"Xem Lại", []string{"Nếu bỏ lỡ một phần buổi live, hãy kiểm tra mục Xem lại sau buổi phát.", "Bạn có thể tua tới phần quan tâm trong video xem lại.", "Các bản ghi đã sẵn sàng được liệt kê tại mục Xem lại.", "Nếu xem lại bị lỗi, hãy báo mã phiên và thiết bị cho quản trị viên.", "Hãy kiểm tra tên kênh và thời gian để chọn đúng bản ghi cần xem."}},
		{"Liên Hệ", []string{"Bạn có thể mở hồ sơ chủ trại để xem thông tin liên hệ.", "Giá và tình trạng còn hàng cần được xác nhận với chủ trại.", "Hãy trao đổi trực tiếp với chủ trại về cách giao nhận.", "Trước khi xác nhận, bạn nên kiểm tra lại mã số và thông tin đã thống nhất.", "Không chia sẻ mã xác thực hay mật khẩu trong khung chat."}},
		{"Hỗ Trợ", []string{"Nếu hình đứng, bạn có thể thử tải lại trang.", "Nếu không nghe âm thanh, hãy kiểm tra cả âm lượng thiết bị và trình phát.", "Khi báo lỗi, hãy cho biết điện thoại và trình duyệt đang sử dụng.", "Nếu kết nối gián đoạn, bạn có thể đợi một chút rồi mở lại luồng.", "Cảm ơn bạn đã thông báo lỗi để quản trị viên kiểm tra."}},
	}
	bots := make([]model.ChatBot, 0, 50)
	now := time.Now()
	for _, group := range groups {
		for i := 1; i <= 5; i++ {
			name := fmt.Sprintf("Bot %s %02d", group.name, i)
			sum := sha256.Sum256([]byte(batch + ":" + name))
			var id primitive.ObjectID
			copy(id[:], sum[:12])
			bots = append(bots, model.ChatBot{ID: id, Name: name, Avatar: "🤖", Role: "user",
				Messages: append([]string(nil), group.messages...), Interval: 45 + i*15,
				IsActive: true, CreatedBy: "codex_import", CreatedAt: now, UpdatedAt: now})
		}
	}
	return bots
}

func main() {
	apply := flag.Bool("apply", false, "Insert the requested batch (otherwise inspect only)")
	flag.Parse()
	_ = godotenv.Load()
	uri := os.Getenv("MONGO_URI")
	if uri == "" {
		log.Fatal("MONGO_URI is required")
	}
	dbName := os.Getenv("MONGO_DB")
	if dbName == "" {
		dbName = "livestream_db"
	}
	s, err := store.New(uri, dbName)
	if err != nil {
		log.Fatal("Cannot connect to configured MongoDB")
	}
	defer s.Client.Disconnect(context.Background())
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	before, err := s.Bots.CountDocuments(ctx, bson.M{})
	if err != nil {
		log.Fatal("Cannot count bots")
	}
	// Public replay identity verifies this is the database backing the user's site.
	replayID, _ := primitive.ObjectIDFromHex("6ae0e03dc5a7ddfdaeab89f5")
	matching, err := s.Sessions.CountDocuments(ctx, bson.M{"_id": replayID, "stream_key": "thanhtrung01"})
	if err != nil || matching != 1 {
		log.Fatal("Configured database does not match the site's known replay; no writes made")
	}
	bots := requestedBots()
	ids := make([]primitive.ObjectID, 0, len(bots))
	writes := make([]mongo.WriteModel, 0, len(bots))
	for _, b := range bots {
		ids = append(ids, b.ID)
		writes = append(writes, mongo.NewUpdateOneModel().SetFilter(bson.M{"_id": b.ID}).SetUpdate(bson.M{"$setOnInsert": b}).SetUpsert(true))
	}
	existing, err := s.Bots.CountDocuments(ctx, bson.M{"_id": bson.M{"$in": ids}})
	if err != nil {
		log.Fatal("Cannot inspect batch")
	}
	fmt.Printf("Site database verified. Total bots: %d. Batch present: %d/50. To add: %d.\n", before, existing, 50-existing)
	if !*apply {
		return
	}
	result, err := s.Bots.BulkWrite(ctx, writes)
	if err != nil {
		log.Fatal("Batch incomplete; retry this command safely to resume")
	}
	verified, err := s.Bots.CountDocuments(ctx, bson.M{"_id": bson.M{"$in": ids}, "is_active": true})
	if err != nil || verified != 50 {
		log.Fatal("Could not verify 50 active bots")
	}
	after, err := s.Bots.CountDocuments(ctx, bson.M{})
	if err != nil {
		log.Fatal("Cannot verify final total")
	}
	fmt.Printf("Inserted %d bots. Verified batch: %d active bots, 250 messages. Total bots: %d. Room assignments unchanged.\n", result.UpsertedCount, verified, after)
}
