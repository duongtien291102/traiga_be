package stream_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"livestream-be/internal/stream"
)

func TestMaskIP(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"", "***"},
		{"103.21.244.55", "103.21.244.***"},
		{"192.168.1.1:8000", "192.168.1.***"},
		{"10.0.0.1", "10.0.0.***"},
		{"unknown", "***"},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got := stream.MaskIP(tc.input)
			if got != tc.expected {
				t.Errorf("MaskIP(%q) = %q; want %q", tc.input, got, tc.expected)
			}
		})
	}
}

func TestGenerateStreamKey(t *testing.T) {
	k1, err1 := stream.GenerateStreamKey()
	if err1 != nil || len(k1) != 64 {
		t.Fatalf("GenerateStreamKey failed or length mismatch: %v, len=%d", err1, len(k1))
	}

	k2, err2 := stream.GenerateStreamKey()
	if err2 != nil || len(k2) != 64 {
		t.Fatalf("GenerateStreamKey failed: %v", err2)
	}

	if k1 == k2 {
		t.Errorf("GenerateStreamKey produced identical consecutive keys")
	}
}

func TestVerifySRSWebhookSecret(t *testing.T) {
	orig := os.Getenv("SRS_WEBHOOK_SECRET")
	defer os.Setenv("SRS_WEBHOOK_SECRET", orig)

	// Case 1: No secret configured -> allowed by default
	os.Unsetenv("SRS_WEBHOOK_SECRET")
	req := httptest.NewRequest(http.MethodPost, "/auth", nil)
	if !stream.VerifySRSWebhookSecret(req) {
		t.Errorf("Expected true when SRS_WEBHOOK_SECRET is empty")
	}

	// Case 2: Secret configured, provided via header
	os.Setenv("SRS_WEBHOOK_SECRET", "supersecret123")
	reqHeader := httptest.NewRequest(http.MethodPost, "/auth", nil)
	reqHeader.Header.Set("X-SRS-Webhook-Secret", "supersecret123")
	if !stream.VerifySRSWebhookSecret(reqHeader) {
		t.Errorf("Expected true when valid secret in header")
	}

	// Case 3: Secret configured, provided via query param
	reqQuery := httptest.NewRequest(http.MethodPost, "/auth?secret=supersecret123", nil)
	if !stream.VerifySRSWebhookSecret(reqQuery) {
		t.Errorf("Expected true when valid secret in query param")
	}

	// Case 4: Invalid secret
	reqBad := httptest.NewRequest(http.MethodPost, "/auth?secret=wrong", nil)
	if stream.VerifySRSWebhookSecret(reqBad) {
		t.Errorf("Expected false for invalid secret")
	}
}
