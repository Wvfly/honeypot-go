package event

import "sync"

// Bus 内存事件总线：发布/订阅，非阻塞投递（消费者慢时丢弃，不拖垮蜜罐主链路）。
type Bus struct {
	mu          sync.RWMutex
	subscribers map[chan Event]struct{}
}

// NewBus 创建事件总线
func NewBus() *Bus {
	return &Bus{subscribers: make(map[chan Event]struct{})}
}

// Subscribe 订阅事件，返回只读事件 channel
func (b *Bus) Subscribe() chan Event {
	ch := make(chan Event, 512)
	b.mu.Lock()
	b.subscribers[ch] = struct{}{}
	b.mu.Unlock()
	return ch
}

// Unsubscribe 取消订阅
func (b *Bus) Unsubscribe(ch chan Event) {
	b.mu.Lock()
	delete(b.subscribers, ch)
	b.mu.Unlock()
}

// Publish 发布事件，对每个订阅者做非阻塞投递
func (b *Bus) Publish(ev Event) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	for ch := range b.subscribers {
		select {
		case ch <- ev:
		default:
			// 订阅者处理不及，丢弃该事件
		}
	}
}
