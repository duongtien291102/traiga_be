package main

import (
	"strings"
	"testing"
)

func TestRequestedBatch(t *testing.T) {
	bots, retry := requestedBots(), requestedBots()
	if len(bots) != 50 {
		t.Fatalf("got %d bots, want 50", len(bots))
	}
	names, ids := map[string]bool{}, map[string]bool{}
	for i, b := range bots {
		if names[b.Name] || ids[b.ID.Hex()] {
			t.Fatal("duplicate bot")
		}
		names[b.Name], ids[b.ID.Hex()] = true, true
		if !strings.HasPrefix(b.Name, "Bot ") || len(b.Messages) != 5 || !b.IsActive || b.Role != "user" || b.Interval < 60 {
			t.Fatalf("invalid bot: %s", b.Name)
		}
		if b.ID != retry[i].ID {
			t.Fatal("retry would create duplicate bots")
		}
		for _, message := range b.Messages {
			if strings.TrimSpace(message) == "" {
				t.Fatal("empty message")
			}
		}
	}
}
