package main

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
	"net/url"
	"os"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

var streamSecretEncryptionKey []byte
var streamSecretHashKey []byte

const encryptedPublishSecretPrefix = "enc:v1:"

// initStreamKeyCrypto derives separate encryption and lookup keys. A dedicated
// secret is preferred; JWT_SECRET remains a backwards-compatible fallback.
func initStreamKeyCrypto() error {
	master := strings.TrimSpace(os.Getenv("STREAM_KEY_ENCRYPTION_KEY"))
	if master == "" {
		master = string(jwtSecret)
	}
	if len(master) < 32 {
		return errors.New("STREAM_KEY_ENCRYPTION_KEY or JWT_SECRET must contain at least 32 characters")
	}

	enc := sha256.Sum256([]byte("traiga/publish-secret/encryption/v1\x00" + master))
	hash := sha256.Sum256([]byte("traiga/publish-secret/hmac/v1\x00" + master))
	streamSecretEncryptionKey = enc[:]
	streamSecretHashKey = hash[:]
	return nil
}

func ensureStreamKeyCrypto() error {
	if len(streamSecretEncryptionKey) == 32 && len(streamSecretHashKey) == 32 {
		return nil
	}
	return initStreamKeyCrypto()
}

func generatePublishSecret() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

func encryptPublishSecret(secret string) (string, error) {
	if err := ensureStreamKeyCrypto(); err != nil {
		return "", err
	}
	block, err := aes.NewCipher(streamSecretEncryptionKey)
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

func decryptPublishSecret(encrypted string) (string, error) {
	if err := ensureStreamKeyCrypto(); err != nil {
		return "", err
	}
	if !strings.HasPrefix(encrypted, encryptedPublishSecretPrefix) {
		return "", errors.New("publish secret is not encrypted with a supported version")
	}
	encoded, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(encrypted, encryptedPublishSecretPrefix))
	if err != nil {
		return "", fmt.Errorf("decode encrypted publish secret: %w", err)
	}
	block, err := aes.NewCipher(streamSecretEncryptionKey)
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
	plaintext, err := aead.Open(nil, nonce, ciphertext, []byte(encryptedPublishSecretPrefix))
	if err != nil {
		return "", fmt.Errorf("decrypt publish secret: %w", err)
	}
	return string(plaintext), nil
}

func hashPublishSecret(secret string) (string, error) {
	if err := ensureStreamKeyCrypto(); err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, streamSecretHashKey)
	_, _ = mac.Write([]byte(secret))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

func publishSecretMatches(secret, storedHash string) bool {
	if secret == "" || storedHash == "" {
		return false
	}
	actual, err := hashPublishSecret(secret)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(actual), []byte(storedHash)) == 1
}

func publishSecretFromSRSParam(param string) string {
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

func preparePublishSecret(key *StreamKey) error {
	if key == nil {
		return errors.New("stream key is nil")
	}
	secret := strings.TrimSpace(key.PublishSecret)
	if secret == "" {
		var err error
		secret, err = generatePublishSecret()
		if err != nil {
			return err
		}
	}
	ciphertext, err := encryptPublishSecret(secret)
	if err != nil {
		return err
	}
	digest, err := hashPublishSecret(secret)
	if err != nil {
		return err
	}
	key.PublishSecret = secret
	key.PublishSecretEncrypted = ciphertext
	key.PublishSecretHash = digest
	return nil
}

func hydratePublishSecret(key *StreamKey) error {
	if key == nil {
		return errors.New("stream key is nil")
	}
	if key.PublishSecret != "" {
		return nil
	}
	secret, err := decryptPublishSecret(key.PublishSecretEncrypted)
	if err != nil {
		return err
	}
	key.PublishSecret = secret
	return nil
}

// migratePublishSecrets initializes a private publish credential for legacy
// rooms and verifies existing ciphertext before the service accepts publishes.
func migratePublishSecrets(ctx context.Context) error {
	if keysColl == nil {
		return errors.New("stream key database is unavailable")
	}
	cursor, err := keysColl.Find(ctx, bson.M{})
	if err != nil {
		return err
	}
	defer cursor.Close(ctx)

	keys := make([]StreamKey, 0)
	if err := cursor.All(ctx, &keys); err != nil {
		return err
	}
	for i := range keys {
		key := &keys[i]
		if key.PublishSecretEncrypted != "" && key.PublishSecretHash != "" {
			if _, err := decryptPublishSecret(key.PublishSecretEncrypted); err == nil {
				continue
			} else {
				return fmt.Errorf("cannot decrypt publish secret for room %s: %w", key.ID.Hex(), err)
			}
		}

		if key.PublishSecretEncrypted != "" {
			secret, err := decryptPublishSecret(key.PublishSecretEncrypted)
			if err != nil {
				return fmt.Errorf("cannot decrypt publish secret for room %s: %w", key.ID.Hex(), err)
			}
			key.PublishSecret = secret
		}
		if err := preparePublishSecret(key); err != nil {
			return err
		}
		filter := bson.M{"_id": key.ID}
		update := bson.M{"$set": bson.M{
			"publish_secret_enc":  key.PublishSecretEncrypted,
			"publish_secret_hash": key.PublishSecretHash,
			"updated_at":          time.Now(),
		}}
		if _, err := keysColl.UpdateOne(ctx, filter, update); err != nil {
			return fmt.Errorf("migrate publish secret for room %s: %w", key.ID.Hex(), err)
		}
	}
	return nil
}

func streamKeyForStorage(key StreamKey) (StreamKey, error) {
	if key.PublishSecret == "" {
		if err := preparePublishSecret(&key); err != nil {
			return StreamKey{}, err
		}
	} else if key.PublishSecretEncrypted == "" || key.PublishSecretHash == "" {
		if err := preparePublishSecret(&key); err != nil {
			return StreamKey{}, err
		}
	}
	return key, nil
}

func insertStreamKey(ctx context.Context, key StreamKey) (StreamKey, error) {
	storedKey, err := streamKeyForStorage(key)
	if err != nil {
		return StreamKey{}, err
	}
	result, err := keysColl.InsertOne(ctx, storedKey)
	if err != nil {
		return StreamKey{}, err
	}
	storedKey.ID = result.InsertedID.(primitive.ObjectID)
	return storedKey, nil
}

func findStreamKeyByRoomID(ctx context.Context, roomID string) (StreamKey, error) {
	var key StreamKey
	err := keysColl.FindOne(ctx, bson.M{"key": strings.TrimSpace(roomID)}).Decode(&key)
	return key, err
}

func findStreamKeyByID(ctx context.Context, id primitive.ObjectID) (StreamKey, error) {
	var key StreamKey
	err := keysColl.FindOne(ctx, bson.M{"_id": id}).Decode(&key)
	return key, err
}
