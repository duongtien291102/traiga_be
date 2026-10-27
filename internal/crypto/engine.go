package crypto

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/url"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"

	"livestream-be/internal/model"
)

const EncryptedPublishSecretPrefix = "enc:v1:"

// Engine quản lý các khóa mã hóa và thuật toán bảo vệ khóa phát livestream.
type Engine struct {
	EncryptionKey []byte
	HashKey       []byte
	FallbackKey   []byte
}

// NewEngine khởi tạo Engine với master secret và fallback secret.
func NewEngine(masterSecret, fallbackSecret string) (*Engine, error) {
	if len(masterSecret) < 32 {
		return nil, errors.New("master secret must contain at least 32 characters")
	}

	enc := sha256.Sum256([]byte("traiga/publish-secret/encryption/v1\x00" + masterSecret))
	hash := sha256.Sum256([]byte("traiga/publish-secret/hmac/v1\x00" + masterSecret))

	var fallback []byte
	if len(fallbackSecret) >= 32 {
		fbEnc := sha256.Sum256([]byte("traiga/publish-secret/encryption/v1\x00" + fallbackSecret))
		fallback = fbEnc[:]
	}

	return &Engine{
		EncryptionKey: enc[:],
		HashKey:       hash[:],
		FallbackKey:   fallback,
	}, nil
}

// GeneratePublishSecret tạo ngẫu nhiên một khóa phát bảo mật 32 bytes URL-safe.
func (e *Engine) GeneratePublishSecret() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

// Encrypt mã hóa secret bằng khóa chính (AES-256-GCM).
func (e *Engine) Encrypt(secret string) (string, error) {
	if e == nil || len(e.EncryptionKey) != 32 {
		return "", errors.New("crypto engine is not properly initialized")
	}
	block, err := aes.NewCipher(e.EncryptionKey)
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
	ciphertext := aead.Seal(nil, nonce, []byte(secret), []byte(EncryptedPublishSecretPrefix))
	encoded := append(nonce, ciphertext...)
	return EncryptedPublishSecretPrefix + base64.RawURLEncoding.EncodeToString(encoded), nil
}

// Decrypt giải mã secret bằng khóa chính.
func (e *Engine) Decrypt(encrypted string) (string, error) {
	if e == nil || len(e.EncryptionKey) != 32 {
		return "", errors.New("crypto engine is not properly initialized")
	}
	return e.decryptWithKey(encrypted, e.EncryptionKey)
}

func (e *Engine) decryptWithKey(encrypted string, key []byte) (string, error) {
	if len(key) != 32 {
		return "", errors.New("invalid encryption key length")
	}
	if !strings.HasPrefix(encrypted, EncryptedPublishSecretPrefix) {
		return "", errors.New("publish secret is not encrypted with a supported version")
	}
	encoded, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(encrypted, EncryptedPublishSecretPrefix))
	if err != nil {
		return "", fmt.Errorf("decode encrypted publish secret: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(encoded) < aead.NonceSize() {
		return "", errors.New("encrypted publish secret is truncated")
	}
	nonce, ciphertext := encoded[:aead.NonceSize()], encoded[aead.NonceSize():]
	plaintext, err := aead.Open(nil, nonce, ciphertext, []byte(EncryptedPublishSecretPrefix))
	if err != nil {
		return "", fmt.Errorf("decrypt publish secret: %w", err)
	}
	return string(plaintext), nil
}

// DecryptWithFallback thử giải mã bằng khóa chính trước, nếu thất bại sẽ thử fallback key.
func (e *Engine) DecryptWithFallback(encrypted string) (string, bool, error) {
	plaintext, err := e.Decrypt(encrypted)
	if err == nil {
		return plaintext, false, nil
	}

	fallbackKey := e.FallbackKey
	if len(fallbackKey) == 32 && subtle.ConstantTimeCompare(e.EncryptionKey, fallbackKey) != 1 {
		if s, decErr := e.decryptWithKey(encrypted, fallbackKey); decErr == nil {
			return s, true, nil
		}
	}
	return "", false, err
}

// Hash tạo digest HMAC-SHA256 của secret để so khớp không cần giải mã.
func (e *Engine) Hash(secret string) (string, error) {
	if e == nil || len(e.HashKey) != 32 {
		return "", errors.New("crypto engine is not properly initialized")
	}
	mac := hmac.New(sha256.New, e.HashKey)
	_, _ = mac.Write([]byte(secret))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

// Matches so sánh secret với storedHash bằng Constant-Time comparison chống timing attack.
func (e *Engine) Matches(secret, storedHash string) bool {
	if secret == "" || storedHash == "" {
		return false
	}
	actual, err := e.Hash(secret)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(actual), []byte(storedHash)) == 1
}

// ExtractSecretFromParam bóc tách publish_secret từ query string của SRS Webhook.
func (e *Engine) ExtractSecretFromParam(param string) string {
	param = strings.TrimSpace(param)
	if param == "" {
		return ""
	}
	values, err := url.ParseQuery(strings.TrimPrefix(param, "?"))
	if err != nil {
		return ""
	}
	return values.Get("publish_secret")
}

// PrepareStreamKey chuẩn bị secret, ciphertext và hash cho StreamKey.
func (e *Engine) PrepareStreamKey(key *model.StreamKey) error {
	if key == nil {
		return errors.New("stream key is nil")
	}
	secret := strings.TrimSpace(key.PublishSecret)
	if secret == "" {
		var err error
		secret, err = e.GeneratePublishSecret()
		if err != nil {
			return err
		}
	}
	ciphertext, err := e.Encrypt(secret)
	if err != nil {
		return err
	}
	digest, err := e.Hash(secret)
	if err != nil {
		return err
	}
	key.PublishSecret = secret
	key.PublishSecretEncrypted = ciphertext
	key.PublishSecretHash = digest
	return nil
}

// HydrateStreamKey giải mã PublishSecret từ ciphertext nếu key.PublishSecret chưa có.
func (e *Engine) HydrateStreamKey(key *model.StreamKey) error {
	if key == nil {
		return errors.New("stream key is nil")
	}
	if key.PublishSecret != "" {
		return nil
	}
	secret, err := e.Decrypt(key.PublishSecretEncrypted)
	if err != nil {
		return err
	}
	key.PublishSecret = secret
	return nil
}

// MigratePublishSecrets quét và tự động nâng cấp/cô lập các key phát trong collection.
func (e *Engine) MigratePublishSecrets(
	ctx context.Context,
	coll *mongo.Collection,
	recordAccessLog func(username, role, action, ip, details string),
) error {
	if coll == nil {
		return errors.New("stream key database is unavailable")
	}
	cursor, err := coll.Find(ctx, bson.M{})
	if err != nil {
		return err
	}
	defer cursor.Close(ctx)

	keys := make([]model.StreamKey, 0)
	if err := cursor.All(ctx, &keys); err != nil {
		return err
	}

	for i := range keys {
		key := &keys[i]
		if key.PublishSecretEncrypted != "" && key.PublishSecretHash != "" {
			secret, usedFallback, err := e.DecryptWithFallback(key.PublishSecretEncrypted)
			if err == nil {
				if usedFallback {
					// Auto-heal: giải mã bằng fallback key -> nâng cấp sang primary key mới
					key.PublishSecret = secret
					if err := e.PrepareStreamKey(key); err != nil {
						log.Printf("⚠️ Không thể chuẩn bị secret mới cho phòng %s: %v", key.ID.Hex(), err)
						continue
					}
					filter := bson.M{"_id": key.ID}
					update := bson.M{"$set": bson.M{
						"publish_secret_enc":  key.PublishSecretEncrypted,
						"publish_secret_hash": key.PublishSecretHash,
						"updated_at":          time.Now(),
					}}
					if _, err := coll.UpdateOne(ctx, filter, update); err != nil {
						log.Printf("⚠️ Lỗi cập nhật auto-heal publish secret cho phòng %s: %v", key.ID.Hex(), err)
						continue
					}
					log.Printf("⚠️ [AUTO-HEAL] Phòng '%s' đã tự động nâng cấp khóa mã hóa mới", key.ID.Hex())
					if recordAccessLog != nil {
						recordAccessLog("system", "systemadmin", "key_auto_healed", "127.0.0.1", fmt.Sprintf("Phòng %s được nâng cấp lên khóa mã hóa mới", key.ID.Hex()))
					}
				}
				continue
			}

			// Key corrupt: cô lập an toàn
			log.Printf("⛔ [SECURITY QUARANTINE] Phòng '%s' có khóa phát bị hỏng, đã tạm thời vô hiệu hóa (is_active: false): %v", key.ID.Hex(), err)
			filter := bson.M{"_id": key.ID}
			update := bson.M{"$set": bson.M{
				"is_active":  false,
				"updated_at": time.Now(),
			}}
			if _, updErr := coll.UpdateOne(ctx, filter, update); updErr != nil {
				log.Printf("⚠️ Không thể cập nhật trạng thái cô lập cho phòng %s: %v", key.ID.Hex(), updErr)
			}
			if recordAccessLog != nil {
				recordAccessLog("system", "systemadmin", "stream_key_corrupted", "127.0.0.1", fmt.Sprintf("Phòng %s bị hỏng khóa phát, đã tạm thời vô hiệu hóa", key.ID.Hex()))
			}
			continue
		}

		if key.PublishSecretEncrypted != "" {
			secret, _, err := e.DecryptWithFallback(key.PublishSecretEncrypted)
			if err != nil {
				log.Printf("⛔ [SECURITY QUARANTINE] Phòng '%s' có khóa phát legacy bị hỏng, đã tạm thời vô hiệu hóa (is_active: false): %v", key.ID.Hex(), err)
				filter := bson.M{"_id": key.ID}
				update := bson.M{"$set": bson.M{
					"is_active":  false,
					"updated_at": time.Now(),
				}}
				if _, updErr := coll.UpdateOne(ctx, filter, update); updErr != nil {
					log.Printf("⚠️ Không thể cô lập phòng %s: %v", key.ID.Hex(), updErr)
				}
				if recordAccessLog != nil {
					recordAccessLog("system", "systemadmin", "stream_key_corrupted", "127.0.0.1", fmt.Sprintf("Phòng %s bị hỏng khóa phát legacy, đã tạm thời vô hiệu hóa", key.ID.Hex()))
				}
				continue
			}
			key.PublishSecret = secret
		}

		if err := e.PrepareStreamKey(key); err != nil {
			log.Printf("⚠️ Không thể khởi tạo publish secret cho phòng %s: %v", key.ID.Hex(), err)
			continue
		}
		filter := bson.M{"_id": key.ID}
		update := bson.M{"$set": bson.M{
			"publish_secret_enc":  key.PublishSecretEncrypted,
			"publish_secret_hash": key.PublishSecretHash,
			"updated_at":          time.Now(),
		}}
		if _, err := coll.UpdateOne(ctx, filter, update); err != nil {
			log.Printf("⚠️ Lỗi lưu publish secret mới cho phòng %s: %v", key.ID.Hex(), err)
			continue
		}
	}
	return nil
}
