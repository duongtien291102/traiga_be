package crypto

import (
	"testing"
)

func TestEngine_EncryptDecrypt(t *testing.T) {
	master := "master-key-very-secret-at-least-32-chars!"
	engine, err := NewEngine(master, "")
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	secret, err := engine.GeneratePublishSecret()
	if err != nil {
		t.Fatalf("failed to generate secret: %v", err)
	}

	ciphertext, err := engine.Encrypt(secret)
	if err != nil {
		t.Fatalf("failed to encrypt secret: %v", err)
	}

	plaintext, err := engine.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("failed to decrypt ciphertext: %v", err)
	}

	if plaintext != secret {
		t.Fatalf("decrypted %q != original %q", plaintext, secret)
	}
}

func TestEngine_FallbackKey(t *testing.T) {
	primaryKey := "primary-secret-key-at-least-32-chars-long!"
	fallbackKey := "fallback-secret-key-at-least-32-chars-long!"

	// Engine cũ dùng fallbackKey làm primary
	oldEngine, err := NewEngine(fallbackKey, "")
	if err != nil {
		t.Fatalf("failed to create old engine: %v", err)
	}
	oldCiphertext, err := oldEngine.Encrypt("my-secret-stream-key-123")
	if err != nil {
		t.Fatalf("failed to encrypt with old engine: %v", err)
	}

	// Engine mới có primaryKey và fallbackKey
	newEngine, err := NewEngine(primaryKey, fallbackKey)
	if err != nil {
		t.Fatalf("failed to create new engine: %v", err)
	}

	decrypted, usedFallback, err := newEngine.DecryptWithFallback(oldCiphertext)
	if err != nil {
		t.Fatalf("expected fallback decryption to succeed, got error: %v", err)
	}
	if !usedFallback {
		t.Fatalf("expected usedFallback to be true")
	}
	if decrypted != "my-secret-stream-key-123" {
		t.Fatalf("expected 'my-secret-stream-key-123', got %q", decrypted)
	}
}

func TestEngine_HashAndMatches(t *testing.T) {
	master := "master-key-very-secret-at-least-32-chars!"
	engine, err := NewEngine(master, "")
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	secret := "secret-token-value-12345"
	hash, err := engine.Hash(secret)
	if err != nil {
		t.Fatalf("failed to hash secret: %v", err)
	}

	if !engine.Matches(secret, hash) {
		t.Fatalf("expected secret to match its hash")
	}

	if engine.Matches("wrong-secret", hash) {
		t.Fatalf("wrong secret should not match hash")
	}
}
