// Package detect 行为分析层：订阅事件总线，规则匹配、按连接累计风险评分、告警。
// 告警同时发布为事件（入库）+ 可选 Webhook 推送。
package detect

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"honeypot-go/internal/config"
	"honeypot-go/internal/event"
)

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

	mu       sync.Mutex
	conns    map[string]*connState
	sessConn map[string]string // session_id -> connection_id
	client   *http.Client
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
	}
}

// Run 消费事件循环，阻塞直到 ctx 取消
func (d *Detector) Run(ctx context.Context) {
	ch := d.bus.Subscribe()
	defer d.bus.Unsubscribe(ch)
	for {
		select {
		case ev := <-ch:
			d.handle(ev)
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
		go d.notify(alertEv)
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
		d.notify(event.New(event.TypeAlert, map[string]any{
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
