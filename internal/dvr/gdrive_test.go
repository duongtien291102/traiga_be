package dvr_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"livestream-be/internal/dvr"
)

func TestWaitForDVRNormalization_Success(t *testing.T) {
	attempts := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/record/live/stream.mp4.avsync-v1" {
			attempts++
			if attempts >= 2 {
				w.WriteHeader(http.StatusOK)
				return
			}
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	vpsRecordURL := ts.URL + "/record/live/stream.mp4"
	start := time.Now()
	dvr.WaitForDVRNormalization(ctx, vpsRecordURL, 6*time.Second)
	elapsed := time.Since(start)

	if attempts < 2 {
		t.Errorf("expected at least 2 attempts, got %d", attempts)
	}
	if elapsed > 8*time.Second {
		t.Errorf("WaitForDVRNormalization took too long: %v", elapsed)
	}
}

func TestWaitForDVRNormalization_Timeout(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	vpsRecordURL := ts.URL + "/record/live/nonexistent.mp4"
	start := time.Now()
	dvr.WaitForDVRNormalization(ctx, vpsRecordURL, 2*time.Second)
	elapsed := time.Since(start)

	if elapsed < 2*time.Second || elapsed > 5*time.Second {
		t.Errorf("expected timeout around 2-3s, got %v", elapsed)
	}
}
