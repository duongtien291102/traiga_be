package bot

import (
	"log"
	"math/rand"
	"strings"
	"sync"
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"

	"livestream-be/internal/model"
)

// RunnerManager quản lý luồng chạy bot tự động theo từng phòng streamKey.
type RunnerManager struct {
	runners        map[string]chan struct{} // streamKey -> stop channel
	mutex          sync.Mutex
	OnSendMessage  func(streamKey string, msg *model.ChatMessage)
	OnSendReaction func(streamKey, emoji, sender string)
}

// NewRunnerManager tạo một RunnerManager mới với callbacks cho tin nhắn và reaction.
func NewRunnerManager(
	onSendMsg func(streamKey string, msg *model.ChatMessage),
	onSendReaction func(streamKey, emoji, sender string),
) *RunnerManager {
	return &RunnerManager{
		runners:        make(map[string]chan struct{}),
		OnSendMessage:  onSendMsg,
		OnSendReaction: onSendReaction,
	}
}

// StartBots khởi động các bot đã chọn cho 1 phòng live.
func (m *RunnerManager) StartBots(streamKey string, bots []model.ChatBot) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Nếu phòng này đang có bot chạy, dừng luồng cũ trước
	if stopCh, exists := m.runners[streamKey]; exists {
		close(stopCh)
		delete(m.runners, streamKey)
	}

	if len(bots) == 0 {
		return
	}

	// Đảm bảo tối đa 5 bot
	if len(bots) > 5 {
		bots = bots[:5]
	}

	stopCh := make(chan struct{})
	m.runners[streamKey] = stopCh

	log.Printf("🤖 [BOT RUNNER] Bắt đầu kích hoạt %d Bot vào phòng live '%s'", len(bots), streamKey)

	go func(key string, botList []model.ChatBot, ch chan struct{}) {
		r := rand.New(rand.NewSource(time.Now().UnixNano()))

		for {
			botIndex := r.Intn(len(botList))
			bot := botList[botIndex]

			baseInterval := bot.Interval
			if baseInterval <= 0 {
				baseInterval = 15
			}
			jitter := r.Intn(9) - 3
			sleepDuration := time.Duration(baseInterval+jitter) * time.Second
			if sleepDuration < 5*time.Second {
				sleepDuration = 5 * time.Second
			}

			select {
			case <-ch:
				log.Printf("⏹️ [BOT RUNNER] Dừng chạy Bot trong phòng live '%s'", key)
				return
			case <-time.After(sleepDuration):
			}

			if len(bot.Messages) > 0 {
				msgIdx := r.Intn(len(bot.Messages))
				text := strings.TrimSpace(bot.Messages[msgIdx])
				if text != "" {
					botRole := bot.Role
					if botRole == "" {
						botRole = "user"
					}

					chatMsg := &model.ChatMessage{
						ID:        primitive.NewObjectID(),
						StreamKey: key,
						Username:  bot.Name,
						Role:      botRole,
						Message:   text,
						Type:      "chat",
						CreatedAt: time.Now(),
					}

					if m.OnSendMessage != nil {
						m.OnSendMessage(key, chatMsg)
					}
					log.Printf("🤖 [BOT CHAT] [%s] %s: %s", key, bot.Name, text)
				}
			}

			// 25% xác suất bot thả reaction cảm xúc ngẫu nhiên
			if r.Float32() < 0.25 {
				emojis := []string{"❤️", "🔥", "👏", "🎉", "💯", "⭐"}
				emoji := emojis[r.Intn(len(emojis))]
				if m.OnSendReaction != nil {
					m.OnSendReaction(key, emoji, bot.Name)
				}
			}
		}
	}(streamKey, bots, stopCh)
}

// StopBots dừng tất cả bot đang chạy trong phòng live.
func (m *RunnerManager) StopBots(streamKey string) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if stopCh, exists := m.runners[streamKey]; exists {
		close(stopCh)
		delete(m.runners, streamKey)
		log.Printf("⏹️ [BOT RUNNER] Đã nhận lệnh dừng Bot cho phòng '%s'", streamKey)
	}
}

// IsRunning kiểm tra xem phòng có bot đang chạy hay không.
func (m *RunnerManager) IsRunning(streamKey string) bool {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	_, exists := m.runners[streamKey]
	return exists
}
