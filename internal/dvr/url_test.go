package dvr_test

import (
	"testing"

	"livestream-be/internal/dvr"
)

func TestNormalizeReplayURL(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		expectedURL   string
		expectedID    string
	}{
		{
			name:        "Empty string",
			input:       "",
			expectedURL: "",
			expectedID:  "",
		},
		{
			name:        "Drive share link with /d/ID/",
			input:       "https://drive.google.com/file/d/1a2b3c4d5e6f7g8h9i0j/view?usp=sharing",
			expectedURL: "https://drive.google.com/file/d/1a2b3c4d5e6f7g8h9i0j/preview",
			expectedID:  "1a2b3c4d5e6f7g8h9i0j",
		},
		{
			name:        "Drive link with id= parameter",
			input:       "https://drive.google.com/open?id=1a2b3c4d5e6f7g8h9i0j",
			expectedURL: "https://drive.google.com/file/d/1a2b3c4d5e6f7g8h9i0j/preview",
			expectedID:  "1a2b3c4d5e6f7g8h9i0j",
		},
		{
			name:        "Pure Drive file ID",
			input:       "1a2b3c4d5e6f7g8h9i0j1234",
			expectedURL: "https://drive.google.com/file/d/1a2b3c4d5e6f7g8h9i0j1234/preview",
			expectedID:  "1a2b3c4d5e6f7g8h9i0j1234",
		},
		{
			name:        "Internal record path without traversal",
			input:       "/record/live/2026-10-27.mp4",
			expectedURL: "/record/live/2026-10-27.mp4",
			expectedID:  "",
		},
		{
			name:        "Path traversal attempt in record path",
			input:       "/record/../../etc/passwd",
			expectedURL: "",
			expectedID:  "",
		},
		{
			name:        "Valid HTTPS MP4 URL",
			input:       "https://storage.googleapis.com/videos/sample.mp4",
			expectedURL: "https://storage.googleapis.com/videos/sample.mp4",
			expectedID:  "",
		},
		{
			name:        "Dangerous javascript scheme (XSS)",
			input:       "javascript:alert(1)",
			expectedURL: "",
			expectedID:  "",
		},
		{
			name:        "Dangerous data URI",
			input:       "data:text/html,<script>alert(1)</script>",
			expectedURL: "",
			expectedID:  "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			url, id := dvr.NormalizeReplayURL(tc.input)
			if url != tc.expectedURL || id != tc.expectedID {
				t.Errorf("NormalizeReplayURL(%q) = (%q, %q); want (%q, %q)",
					tc.input, url, id, tc.expectedURL, tc.expectedID)
			}
		})
	}
}
