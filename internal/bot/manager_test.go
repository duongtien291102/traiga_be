package bot

import (
	"sync/atomic"
	"testing"

	"livestream-be/internal/model"
)

func TestRunnerManager_StartStop(t *testing.T) {
	var sentCount int32
	m := NewRunnerManager(
		func(streamKey string, msg *model.ChatMessage) {
			atomic.AddInt32(&sentCount, 1)
		},
		func(streamKey, emoji, sender string) {},
	)

	streamKey := "test_stream_room_1"

	if m.IsRunning(streamKey) {
		t.Fatalf("expected room not running initially")
	}

	bots := []model.ChatBot{
		{
			Name:     "TestBot1",
			Role:     "user",
			Messages: []string{"Hello test 1", "Hello test 2"},
			Interval: 1, // 1 second
			IsActive: true,
		},
	}

	m.StartBots(streamKey, bots)
	if !m.IsRunning(streamKey) {
		t.Fatalf("expected room running after StartBots")
	}

	// Stop
	m.StopBots(streamKey)
	if m.IsRunning(streamKey) {
		t.Fatalf("expected room not running after StopBots")
	}
}

func TestRunnerManager_Max5Bots(t *testing.T) {
	m := NewRunnerManager(nil, nil)
	bots := make([]model.ChatBot, 10)
	for i := 0; i < 10; i++ {
		bots[i] = model.ChatBot{Name: "Bot", Interval: 10}
	}

	m.StartBots("room_limit", bots)
	if !m.IsRunning("room_limit") {
		t.Fatalf("expected running")
	}
	m.StopBots("room_limit")
}

func TestRunnerManager_EmptyBots(t *testing.T) {
	m := NewRunnerManager(nil, nil)
	m.StartBots("room_empty", []model.ChatBot{})
	if m.IsRunning("room_empty") {
		t.Fatalf("empty bots should not start runner")
	}
}
