package event

import "time"

// Type 事件类型
type Type string

const (
	TypeConnectionOpened Type = "connection.opened"
	TypeConnectionClosed Type = "connection.closed"
	TypeAuthAttempt      Type = "auth.attempt"
	TypeSessionOpened    Type = "session.opened"
	TypeSessionClosed    Type = "session.closed"
	TypeCommandExecuted  Type = "command.executed"
	// M2：网络仿真与文件投递
	TypeDownloadAttempt Type = "network.download_attempt"
	TypeConnectAttempt  Type = "network.connect_attempt"
	TypeFileWritten     Type = "file.written"
	// M2：行为分析告警
	TypeAlert Type = "alert"
)

// Event 统一事件模型：类型 + 时间戳 + 键值数据
// 所有模块通过 Bus 发布，存储/分析/遥测等消费者订阅处理，模块间零耦合。
type Event struct {
	Type Type           `json:"type"`
	Time time.Time      `json:"time"`
	Data map[string]any `json:"data,omitempty"`
}

// New 构造一个事件
func New(t Type, data map[string]any) Event {
	return Event{Type: t, Time: time.Now(), Data: data}
}
