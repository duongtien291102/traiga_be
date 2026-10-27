package chat

import (
	"testing"

	"livestream-be/internal/model"
)

func TestMaskPhoneNumbers(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"Gà đẹp liên hệ 0912345678 nhé", "Gà đẹp liên hệ 091234**** nhé"},
		{"Số em là +84912345678", "Số em là +8491234****"},
		{"Không có số điện thoại", "Không có số điện thoại"},
		{"Số ngắn 12345", "Số ngắn 12345"},
	}

	for _, tt := range tests {
		got := MaskPhoneNumbers(tt.input)
		if got != tt.expected {
			t.Errorf("MaskPhoneNumbers(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestSanitizeChatHistory(t *testing.T) {
	msgs := []model.ChatMessage{
		{Message: "Liên hệ 0912345678"},
	}

	// When canViewPhones = true -> unchanged
	visible := SanitizeChatHistory(msgs, true)
	if visible[0].Message != "Liên hệ 0912345678" {
		t.Errorf("expected original phone, got %q", visible[0].Message)
	}

	// When canViewPhones = false -> masked
	masked := SanitizeChatHistory(msgs, false)
	if masked[0].Message != "Liên hệ 091234****" {
		t.Errorf("expected masked phone, got %q", masked[0].Message)
	}
}
