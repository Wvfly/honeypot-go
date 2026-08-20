// Package detect 行为分析层：订阅事件总线，规则匹配、按连接累计风险评分、告警。
// 告警同时发布为事件（入库）+ 可选 Webhook 推送。
package detect

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"honeypot-go/internal/config"
	"honeypot-go/internal/event"
)

// notifyQueueCap Webhook 推送队列上限：Webhook 慢时宁可丢弃推送也不堆积 goroutine
const notifyQueueCap = 64

// busDropMonitorInterval 事件总线丢弃计数检查周期：总线队列满而被丢弃的事件
// 意味着检测/存储链路处理不及（典型是被攻击者刷海量命令淹没），需及时告警。
const busDropMonitorInterval = 30 * time.Second

// connState 单个连接（攻击源）的风险状态
type connState struct {
	connID   string
	sourceIP string
	score    int
	attempts int
	fails    int
	loggedIn bool
	loginAt  time.Time
	fired    map[string]bool // 已触发规则，避免重复告警
}

// Detector 规则引擎
type Detector struct {
	cfg    config.DetectConfig
	bus    *event.Bus
	logger *slog.Logger

	mu            sync.Mutex
	conns         map[string]*connState
	sessConn      map[string]string // session_id -> connection_id
	client        *http.Client
	notifyCh      chan event.Event // 有界 Webhook 推送队列
	droppedAlerts atomic.Uint64    // 队列满被丢弃的推送数
}

// New 创建检测器
func New(cfg config.DetectConfig, bus *event.Bus, logger *slog.Logger) *Detector {
	return &Detector{
		cfg:      cfg,
		bus:      bus,
		logger:   logger,
		conns:    make(map[string]*connState),
		sessConn: make(map[string]string),
		client:   &http.Client{Timeout: 5 * time.Second},
		notifyCh: make(chan event.Event, notifyQueueCap),
	}
}

// Run 消费事件循环，阻塞直到 ctx 取消
func (d *Detector) Run(ctx context.Context) {
	ch := d.bus.Subscribe()
	defer d.bus.Unsubscribe(ch)
	// Webhook 单 worker 串行推送：告警风暴时队列满即丢弃（计数），避免 goroutine 无限堆积
	go d.webhookWorker(ctx)
	// 监控事件总线丢弃：检测链路被事件风暴淹没时"失明"，运营方无感知
	go d.monitorBusDropped(ctx)
	for {
		select {
		case ev := <-ch:
			d.handle(ev)
		case <-ctx.Done():
			return
		}
	}
}

// monitorBusDropped 周期检查事件总线丢弃计数。窗口内丢弃数增长说明有消费者
// （检测/存储）处理不及，通常是攻击者刷海量命令/事件试图淹没分析链路——
// 这是检测"失明"的前兆。发现时发布 event_bus_overload 告警（入库 + Webhook），
// 与普通攻击告警形成闭环。告警自身也走同一总线：总线满时可能被丢，但日志始终可见。
func (d *Detector) monitorBusDropped(ctx context.Context) {
	t := time.NewTicker(busDropMonitorInterval)
	defer t.Stop()
	var last uint64
	for {
		select {
		case <-t.C:
			cur := d.bus.Dropped()
			if cur <= last {
				last = cur
				continue
			}
			drop := cur - last
			last = cur
			d.bus.Publish(event.New(event.TypeAlert, map[string]any{
				"rule_name":         "event_bus_overload",
				"severity":          "medium",
				"source_ip":         "internal",
				"evidence":          fmt.Sprintf("event bus dropped %d events in last window (total %d)", drop, cur),
				"dropped_in_window": drop,
			}))
			d.logger.Warn("event bus dropping events, detection may be degraded",
				"dropped_in_window", drop,
				"dropped_total", cur)
		case <-ctx.Done():
			return
		}
	}
}

// handle 按事件类型维护状态并跑规则
func (d *Detector) handle(ev event.Event) {
	switch ev.Type {
	case event.TypeConnectionOpened:
		d.mu.Lock()
		d.conns[eventStr(ev, "connection_id")] = &connState{
			connID:   eventStr(ev, "connection_id"),
			sourceIP: eventStr(ev, "source_ip"),
			fired:    make(map[string]bool),
		}
		d.mu.Unlock()

	case event.TypeConnectionClosed:
		d.mu.Lock()
		st := d.conns[eventStr(ev, "connection_id")]
		if st != nil {
			d.finalReport(ev, st)
			delete(d.conns, st.connID)
		}
		d.mu.Unlock()

	case event.TypeAuthAttempt:
		connID := eventStr(ev, "connection_id")
		d.mu.Lock()
		st := d.conns[connID]
		if st == nil {
			st = &connState{connID: connID, sourceIP: eventStr(ev, "source_ip"), fired: make(map[string]bool)}
			d.conns[connID] = st
		}
		st.attempts++
		if eventBool(ev, "success") {
			st.loggedIn = true
			st.loginAt = time.Now()
		} else {
			st.fails++
		}
		st2 := st
		d.mu.Unlock()
		d.check(ev, st2)

	case event.TypeSessionOpened:
		d.mu.Lock()
		d.sessConn[eventStr(ev, "session_id")] = eventStr(ev, "connection_id")
		d.mu.Unlock()

	case event.TypeSessionClosed:
		// 会话关闭即删除映射，防止 map 只增不减导致内存泄漏
		d.mu.Lock()
		delete(d.sessConn, eventStr(ev, "session_id"))
		d.mu.Unlock()

	case event.TypeCommandExecuted, event.TypeDownloadAttempt,
		event.TypeConnectAttempt, event.TypeFileWritten:
		connID := d.connOf(ev)
		if connID == "" {
			return
		}
		d.mu.Lock()
		st := d.conns[connID]
		if st == nil {
			st = &connState{connID: connID, fired: make(map[string]bool)}
			d.conns[connID] = st
		}
		st2 := st
		d.mu.Unlock()
		d.check(ev, st2)
	}
}

// connOf 从事件的 session_id 反查 connection_id
func (d *Detector) connOf(ev event.Event) string {
	sid := eventStr(ev, "session_id")
	if sid == "" {
		return ""
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.sessConn[sid]
}

// check 跑全部规则；命中则加分并发告警
func (d *Detector) check(ev event.Event, st *connState) {
	if st == nil {
		return
	}
	for i := range rules {
		r := &rules[i]
		if st.fired[r.Name] {
			continue
		}
		if !r.Match(ev, st) {
			continue
		}
		st.fired[r.Name] = true
		st.score += r.Points
		d.alert(ev, st, *r)
	}
}

// alert 发布告警事件（store 入库）+ 可选 Webhook
func (d *Detector) alert(ev event.Event, st *connState, r Rule) {
	sev := r.Severity
	if s := severityForScore(st.score); r.Points > 0 {
		sev = s // 告警级别按累计分，反映整体风险
	}
	alertEv := event.New(event.TypeAlert, map[string]any{
		"connection_id": st.connID,
		"session_id":    eventStr(ev, "session_id"),
		"source_ip":     st.sourceIP,
		"rule_name":     r.Name,
		"severity":      sev,
		"score":         st.score,
		"evidence":      eventStr(ev, "command") + eventStr(ev, "url") + eventStr(ev, "path") + eventStr(ev, "target"),
	})
	d.bus.Publish(alertEv)
	d.logger.Warn("alert fired",
		"rule", r.Name,
		"severity", sev,
		"score", st.score,
		"source_ip", st.sourceIP,
		"connection_id", st.connID,
	)
	if d.cfg.WebhookURL != "" {
		d.enqueueNotify(alertEv)
	}
}

// enqueueNotify 非阻塞入队 Webhook 推送；队列满则丢弃并计数
func (d *Detector) enqueueNotify(ev event.Event) {
	select {
	case d.notifyCh <- ev:
	default:
		d.droppedAlerts.Add(1)
		d.logger.Warn("webhook queue full, alert notification dropped", "rule", eventStr(ev, "rule_name"))
	}
}

// webhookWorker 串行消费告警推送，防止 Webhook 慢时 goroutine 无限堆积
func (d *Detector) webhookWorker(ctx context.Context) {
	for {
		select {
		case ev := <-d.notifyCh:
			d.notify(ev)
		case <-ctx.Done():
			return
		}
	}
}

// finalReport 连接关闭时汇总风险状态（若未发过 critical 级告警）
func (d *Detector) finalReport(ev event.Event, st *connState) {
	if st.score == 0 || st.fired["final_report"] {
		return
	}
	st.fired["final_report"] = true
	sev := severityForScore(st.score)
	d.bus.Publish(event.New(event.TypeAlert, map[string]any{
		"connection_id": st.connID,
		"source_ip":     st.sourceIP,
		"rule_name":     "session_risk_summary",
		"severity":      sev,
		"score":         st.score,
		"evidence":      "total score for session",
	}))
	if d.cfg.WebhookURL != "" {
		d.enqueueNotify(event.New(event.TypeAlert, map[string]any{
			"connection_id": st.connID,
			"source_ip":     st.sourceIP,
			"rule_name":     "session_risk_summary",
			"severity":      sev,
			"score":         st.score,
		}))
	}
}

// notify 推送告警到 Webhook
func (d *Detector) notify(ev event.Event) {
	payload, _ := json.Marshal(map[string]any{
		"type":      ev.Type,
		"time":      ev.Time.Format(time.RFC3339Nano),
		"data":      ev.Data,
		"source_ip": eventStr(ev, "source_ip"),
	})
	resp, err := d.client.Post(d.cfg.WebhookURL, "application/json", bytes.NewReader(payload))
	if err != nil {
		d.logger.Warn("webhook notify failed", "error", err)
		return
	}
	_ = resp.Body.Close()
}
