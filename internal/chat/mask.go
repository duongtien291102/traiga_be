package chat

import (
	"regexp"
	"strings"

	"livestream-be/internal/model"
)

var phoneNumberPattern = regexp.MustCompile(`(\+?84|0)[0-9][0-9 ().-]{6,18}`)

// MaskPhoneNumbers che bốn chữ số cuối của số điện thoại Việt Nam trong chat.
func MaskPhoneNumbers(message string) string {
	return phoneNumberPattern.ReplaceAllStringFunc(message, func(candidate string) string {
		trimmed := strings.TrimRight(candidate, " .-)")
		digits := make([]int, 0, len(trimmed))
		for i, r := range trimmed {
			if r >= '0' && r <= '9' {
				digits = append(digits, i)
			}
		}
		prefix := strings.TrimSpace(trimmed)
		validLength := len(digits) >= 9 && len(digits) <= 11
		if strings.HasPrefix(prefix, "+84") || strings.HasPrefix(prefix, "84") {
			validLength = len(digits) >= 11 && len(digits) <= 12
		}
		if !validLength {
			return candidate
		}
		masked := []rune(candidate)
		for _, pos := range digits[len(digits)-4:] {
			masked[pos] = '*'
		}
		return string(masked)
	})
}

// SanitizeChatHistory lọc số điện thoại trong lịch sử chat nếu người xem không có quyền xem.
func SanitizeChatHistory(messages []model.ChatMessage, canViewPhones bool) []model.ChatMessage {
	if canViewPhones {
		return messages
	}
	for i := range messages {
		messages[i].Message = MaskPhoneNumbers(messages[i].Message)
	}
	return messages
}
