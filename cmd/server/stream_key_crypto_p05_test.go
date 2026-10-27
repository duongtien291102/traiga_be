package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/integration/mtest"
)

// Helper: Mã hóa chuỗi secret bằng 1 master key cụ thể phục vụ tạo mock data
func helperEncryptWithMaster(masterKeyStr, secret string) (string, error) {
	encHash := sha256.Sum256([]byte("traiga/publish-secret/encryption/v1\x00" + masterKeyStr))
	block, err := aes.NewCipher(encHash[:])
	if err != nil {
		return "", err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ciphertext := aead.Seal(nil, nonce, []byte(secret), []byte(encryptedPublishSecretPrefix))
	encoded := append(nonce, ciphertext...)
	return encryptedPublishSecretPrefix + base64.RawURLEncoding.EncodeToString(encoded), nil
}

func TestMigratePublishSecrets_Phase05_Safety(t *testing.T) {
	newKeySecret := "new-stream-encryption-key-32-chars-long!"
	oldJwtSecret := "old-jwt-secret-key-at-least-32-chars-long!"

	// Lưu và khôi phục biến toàn cục sau test
	origEnc := streamSecretEncryptionKey
	origHash := streamSecretHashKey
	origJwt := jwtSecret
	defer func() {
		streamSecretEncryptionKey = origEnc
		streamSecretHashKey = origHash
		jwtSecret = origJwt
	}()

	// Thiết lập master key hiện tại = newKeySecret, fallback key = oldJwtSecret
	masterHash := sha256.Sum256([]byte("traiga/publish-secret/encryption/v1\x00" + newKeySecret))
	hashKey := sha256.Sum256([]byte("traiga/publish-secret/hmac/v1\x00" + newKeySecret))
	streamSecretEncryptionKey = masterHash[:]
	streamSecretHashKey = hashKey[:]
	jwtSecret = []byte(oldJwtSecret)

	// Khởi tạo MongoDB Mock Runner
	mt := mtest.New(t, mtest.NewOptions().ClientType(mtest.Mock))

	// Case 1: Empty Collection (Deploy lần đầu, 0 keys) - Bắt buộc return nil không crash
	mt.Run("Case 1: Empty Collection - Return nil without crash", func(mt *mtest.T) {
		origColl := keysColl
		keysColl = mt.Coll
		defer func() { keysColl = origColl }()

		// Mock cursor rỗng (0 documents)
		mt.AddMockResponses(mtest.CreateCursorResponse(0, "livestream_db.stream_keys", mtest.FirstBatch))

		err := migratePublishSecrets(context.Background())
		if err != nil {
			t.Fatalf("Empty collection phải trả về nil, nhưng nhận lỗi: %v", err)
		}
	})

	// Case 1b: Database nil (Guard clause) - Trả về lỗi có kiểm soát, không panic
	t.Run("Case 1b: Database nil - Guard clause returns controlled error", func(t *testing.T) {
		origColl := keysColl
		keysColl = nil
		defer func() { keysColl = origColl }()

		err := migratePublishSecrets(context.Background())
		if err == nil {
			t.Errorf("Mong đợi lỗi khi keysColl == nil, nhưng nhận nil")
		}
	})

	// Case 2: 1 Valid + 1 Corrupt - Phải cô lập key corrupt (is_active: false) và KHÔNG crash
	mt.Run("Case 2: 1 Valid + 1 Corrupt - Quarantine corrupt key", func(mt *mtest.T) {
		origColl := keysColl
		keysColl = mt.Coll
		defer func() { keysColl = origColl }()

		mt.ClearEvents()

		idValid := primitive.NewObjectID()
		validEnc, _ := helperEncryptWithMaster(newKeySecret, "valid-secret-123456")

		idCorrupt := primitive.NewObjectID()
		corruptEnc := encryptedPublishSecretPrefix + "corrupted_invalid_base64_data_here"

		docValid := bson.D{
			{Key: "_id", Value: idValid},
			{Key: "key", Value: "room_valid"},
			{Key: "publish_secret_enc", Value: validEnc},
			{Key: "publish_secret_hash", Value: "some_valid_hash"},
			{Key: "is_active", Value: true},
		}
		docCorrupt := bson.D{
			{Key: "_id", Value: idCorrupt},
			{Key: "key", Value: "room_corrupt"},
			{Key: "publish_secret_enc", Value: corruptEnc},
			{Key: "publish_secret_hash", Value: "some_hash"},
			{Key: "is_active", Value: true},
		}

		mt.AddMockResponses(mtest.CreateCursorResponse(0, "livestream_db.stream_keys", mtest.FirstBatch, docValid, docCorrupt))
		mt.AddMockResponses(mtest.CreateSuccessResponse()) // Mock UpdateOne cho room_corrupt

		err := migratePublishSecrets(context.Background())
		if err != nil {
			mt.Fatalf("Phase 0.5 yêu cầu không được fail-fast khi gặp key hỏng, got: %v", err)
		}

		// VERIFY ĐÚNG HÀNH VI: Phải có đúng 1 lệnh update để mark inactive
		updateEvents := 0
		foundInactiveUpdate := false
		for _, ev := range mt.GetAllStartedEvents() {
			if ev.CommandName == "update" {
				updateEvents++
				cmdStr := ev.Command.String()
				if strings.Contains(cmdStr, `"is_active": false`) || strings.Contains(cmdStr, `"is_active", false`) {
					foundInactiveUpdate = true
				}
			}
		}
		if updateEvents != 1 {
			mt.Errorf("Kỳ vọng đúng 1 lệnh update để cô lập key lỗi, nhưng phát hiện %d lệnh", updateEvents)
		}
		if !foundInactiveUpdate {
			mt.Errorf("Lệnh update không chứa thuộc tính is_active: false để khóa key hỏng!")
		}
	})

	// Case 3: All Valid Keys - Pass mượt mà, KHÔNG phát sinh lệnh update
	mt.Run("Case 3: All Valid Keys - Pass smoothly without DB updates", func(mt *mtest.T) {
		origColl := keysColl
		keysColl = mt.Coll
		defer func() { keysColl = origColl }()

		mt.ClearEvents()

		id1 := primitive.NewObjectID()
		enc1, _ := helperEncryptWithMaster(newKeySecret, "secret-one-123456")
		id2 := primitive.NewObjectID()
		enc2, _ := helperEncryptWithMaster(newKeySecret, "secret-two-123456")

		doc1 := bson.D{
			{Key: "_id", Value: id1},
			{Key: "key", Value: "room_1"},
			{Key: "publish_secret_enc", Value: enc1},
			{Key: "publish_secret_hash", Value: "hash_1"},
			{Key: "is_active", Value: true},
		}
		doc2 := bson.D{
			{Key: "_id", Value: id2},
			{Key: "key", Value: "room_2"},
			{Key: "publish_secret_enc", Value: enc2},
			{Key: "publish_secret_hash", Value: "hash_2"},
			{Key: "is_active", Value: true},
		}

		mt.AddMockResponses(mtest.CreateCursorResponse(0, "livestream_db.stream_keys", mtest.FirstBatch, doc1, doc2))

		err := migratePublishSecrets(context.Background())
		if err != nil {
			mt.Fatalf("Không thể migrate khi toàn bộ key hợp lệ: %v", err)
		}

		// VERIFY: Toàn bộ key đã hợp lệ thì KHÔNG được update lung tung
		for _, ev := range mt.GetAllStartedEvents() {
			if ev.CommandName == "update" {
				mt.Errorf("Phát hiện lệnh update không mong muốn khi toàn bộ key đã hợp lệ!")
			}
		}
	})

	// Case 4: All Corrupt Keys - Cô lập toàn bộ (2 updates is_active: false), server không sập
	mt.Run("Case 4: All Corrupt Keys - Quarantine all without server crash", func(mt *mtest.T) {
		origColl := keysColl
		keysColl = mt.Coll
		defer func() { keysColl = origColl }()

		mt.ClearEvents()

		id1 := primitive.NewObjectID()
		id2 := primitive.NewObjectID()

		doc1 := bson.D{
			{Key: "_id", Value: id1},
			{Key: "key", Value: "room_broken_1"},
			{Key: "publish_secret_enc", Value: encryptedPublishSecretPrefix + "broken_1"},
			{Key: "publish_secret_hash", Value: "hash_1"},
			{Key: "is_active", Value: true},
		}
		doc2 := bson.D{
			{Key: "_id", Value: id2},
			{Key: "key", Value: "room_broken_2"},
			{Key: "publish_secret_enc", Value: encryptedPublishSecretPrefix + "broken_2"},
			{Key: "publish_secret_hash", Value: "hash_2"},
			{Key: "is_active", Value: true},
		}

		mt.AddMockResponses(mtest.CreateCursorResponse(0, "livestream_db.stream_keys", mtest.FirstBatch, doc1, doc2))
		mt.AddMockResponses(mtest.CreateSuccessResponse()) // Mock UpdateOne room 1
		mt.AddMockResponses(mtest.CreateSuccessResponse()) // Mock UpdateOne room 2

		err := migratePublishSecrets(context.Background())
		if err != nil {
			mt.Fatalf("Phase 0.5 yêu cầu cô lập tất cả key hỏng mà không trả về fatal error, got: %v", err)
		}

		// VERIFY: Phải có đúng 2 lệnh update để cô lập cả 2 phòng hỏng
		updateEvents := 0
		for _, ev := range mt.GetAllStartedEvents() {
			if ev.CommandName == "update" {
				updateEvents++
			}
		}
		if updateEvents != 2 {
			mt.Errorf("Kỳ vọng đúng 2 lệnh update để cô lập 2 key hỏng, nhưng phát hiện %d lệnh", updateEvents)
		}
	})

	// Case 5: Dual-Key Auto-heal - Giải mã bằng JWT_SECRET cũ và mã hóa lại bằng NEW_KEY
	mt.Run("Case 5: Dual-Key Fallback - Auto heal legacy JWT_SECRET ciphertext", func(mt *mtest.T) {
		origColl := keysColl
		keysColl = mt.Coll
		defer func() { keysColl = origColl }()

		mt.ClearEvents()

		idLegacy := primitive.NewObjectID()
		rawSecret := "legacy-secret-need-heal-123456"
		legacyEnc, _ := helperEncryptWithMaster(oldJwtSecret, rawSecret)

		docLegacy := bson.D{
			{Key: "_id", Value: idLegacy},
			{Key: "key", Value: "room_legacy"},
			{Key: "publish_secret_enc", Value: legacyEnc},
			{Key: "publish_secret_hash", Value: "old_hash"},
			{Key: "is_active", Value: true},
		}

		mt.AddMockResponses(mtest.CreateCursorResponse(0, "livestream_db.stream_keys", mtest.FirstBatch, docLegacy))
		mt.AddMockResponses(mtest.CreateSuccessResponse()) // Mock UpdateOne lưu bản mã mới

		err := migratePublishSecrets(context.Background())
		if err != nil {
			mt.Fatalf("Dual-key fallback phải giải mã thành công key cũ và auto-heal, got: %v", err)
		}

		// VERIFY 3 ĐIỀU KIỆN NGHIÊM NGẶT (C3b):
		updateEvents := 0
		var newCiphertextInUpdate string

		for _, ev := range mt.GetAllStartedEvents() {
			if ev.CommandName == "update" {
				updateEvents++
				var cmdMap struct {
					Updates []struct {
						U struct {
							Set struct {
								PublishSecretEnc string `bson:"publish_secret_enc"`
							} `bson:"$set"`
						} `bson:"u"`
					} `bson:"updates"`
				}
				// Option A: bson.Unmarshal(ev.Command, &cmdMap)
				if errUnmarshal := bson.Unmarshal(ev.Command, &cmdMap); errUnmarshal == nil && len(cmdMap.Updates) > 0 {
					newCiphertextInUpdate = cmdMap.Updates[0].U.Set.PublishSecretEnc
				}
			}
		}

		if updateEvents != 1 {
			mt.Fatalf("Kỳ vọng đúng 1 lệnh update để lưu bản mã auto-healed, nhưng phát hiện %d lệnh", updateEvents)
		}

		// (a) Ciphertext mới trong DB phải KHÁC ciphertext cũ
		if newCiphertextInUpdate == "" || newCiphertextInUpdate == legacyEnc {
			mt.Errorf("Lỗi: Bản mã trong update command không thay đổi hoặc bị rỗng! Got: %s", newCiphertextInUpdate)
		}

		// (b) Giải mã ciphertext MỚI bằng Master Key MỚI phải cho ra đúng rawSecret ban đầu
		decryptedWithNewKey, errDec := decryptPublishSecret(newCiphertextInUpdate)
		if errDec != nil {
			mt.Fatalf("Không thể giải mã bản mã mới bằng Master Key mới: %v", errDec)
		}
		if decryptedWithNewKey != rawSecret {
			mt.Errorf("Plaintext giải mã không khớp! Mong đợi: %s, Nhận được: %s", rawSecret, decryptedWithNewKey)
		}
	})
}
