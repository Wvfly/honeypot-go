package event

import (
	"sync"
	"sync/atomic"
)

// Bus 内存事件总线：发布/订阅，非阻塞投递（消费者慢时丢弃，不拖垮蜜罐主链路）。
// 被丢弃的事件会累计计数，可通过 Dropped() 观测：持续增长说明存在事件风暴
// （如攻击者刷海量命令淹没分析链路），便于发现检测"失明"风险。
type Bus struct {
	mu          sync.RWMutex
	subscribers map[chan Event]struct{}
	dropped     atomic.Uint64 // 因订阅者队列满而被丢弃的事件总数
}

// NewBus 创建事件总线
func NewBus() *Bus {
	return &Bus{subscribers: make(map[chan Event]struct{})}
}

// Subscribe 订阅事件，返回只读事件 channel
func (b *Bus) Subscribe() chan Event {
	ch := make(chan Event, 2048)
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

// Publish 发布事件，对每个订阅者做非阻塞投递；队列满则丢弃并计数
func (b *Bus) Publish(ev Event) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	for ch := range b.subscribers {
		select {
		case ch <- ev:
		default:
			b.dropped.Add(1)
		}
	}
}

// Dropped 返回因订阅者处理不及而被丢弃的事件总数。
// 若持续快速增长，说明有消费者跟不上，应排查检测/存储链路或增大订阅队列。
func (b *Bus) Dropped() uint64 {
	return b.dropped.Load()
}
