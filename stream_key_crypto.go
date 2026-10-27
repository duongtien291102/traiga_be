package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"strings"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"

	"livestream-be/internal/crypto"
)

var streamSecretEncryptionKey []byte
var streamSecretHashKey []byte
var streamSecretFallbackKey []byte

const encryptedPublishSecretPrefix = crypto.EncryptedPublishSecretPrefix

// initFallbackCrypto derives a fallback encryption key using JWT_SECRET if available.
func initFallbackCrypto() {
	if len(jwtSecret) >= 32 {
		fallbackEnc := sha256.Sum256([]byte("traiga/publish-secret/encryption/v1\x00" + string(jwtSecret)))
		streamSecretFallbackKey = fallbackEnc[:]
	}
}

// initStreamKeyCrypto derives separate encryption and lookup keys.
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
	initFallbackCrypto()
	return nil
}

func ensureStreamKeyCrypto() error {
	if len(streamSecretEncryptionKey) == 32 && len(streamSecretHashKey) == 32 {
		return nil
	}
	return initStreamKeyCrypto()
}

func getCryptoEngine() *crypto.Engine {
	_ = ensureStreamKeyCrypto()
	initFallbackCrypto()
	return &crypto.Engine{
		EncryptionKey: streamSecretEncryptionKey,
		HashKey:       streamSecretHashKey,
		FallbackKey:   streamSecretFallbackKey,
	}
}

func generatePublishSecret() (string, error) {
	return getCryptoEngine().GeneratePublishSecret()
}

func encryptPublishSecret(secret string) (string, error) {
	if err := ensureStreamKeyCrypto(); err != nil {
		return "", err
	}
	return getCryptoEngine().Encrypt(secret)
}

func decryptPublishSecret(encrypted string) (string, error) {
	if err := ensureStreamKeyCrypto(); err != nil {
		return "", err
	}
	return getCryptoEngine().Decrypt(encrypted)
}

func decryptWithKey(encrypted string, key []byte) (string, error) {
	engine := &crypto.Engine{EncryptionKey: key}
	return engine.Decrypt(encrypted)
}

func decryptPublishSecretWithFallback(encrypted string) (string, bool, error) {
	return getCryptoEngine().DecryptWithFallback(encrypted)
}

func hashPublishSecret(secret string) (string, error) {
	if err := ensureStreamKeyCrypto(); err != nil {
		return "", err
	}
	return getCryptoEngine().Hash(secret)
}

func publishSecretMatches(secret, storedHash string) bool {
	return getCryptoEngine().Matches(secret, storedHash)
}

func publishSecretFromSRSParam(param string) string {
	return getCryptoEngine().ExtractSecretFromParam(param)
}

func preparePublishSecret(key *StreamKey) error {
	return getCryptoEngine().PrepareStreamKey(key)
}

func hydratePublishSecret(key *StreamKey) error {
	return getCryptoEngine().HydrateStreamKey(key)
}

func migratePublishSecrets(ctx context.Context) error {
	return getCryptoEngine().MigratePublishSecrets(ctx, keysColl, recordAccessLog)
}

func streamKeyForStorage(key StreamKey) (StreamKey, error) {
	if key.PublishSecret == "" || key.PublishSecretEncrypted == "" || key.PublishSecretHash == "" {
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
