package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"

	"honeypot-go/internal/config"
	"honeypot-go/internal/event"
)

// flushInterval SQLite 批量落盘周期：事件先攒批，每间隔或攒满一批再以单事务提交。
// 原因：modernc.org/sqlite 在 Windows 上每条 Exec 自动提交（创建/删除 journal + fsync）
// 实测耗时 70~190ms，单条提交会把 store 拖到积压直至阻塞；批量后 <2ms/条。
const (
	flushInterval = 250 * time.Millisecond
	flushBatch    = 128
	// cleanupInterval 过期数据清理周期（SQLite 旧记录 + 过期 JSONL）
	cleanupInterval = 6 * time.Hour
)

// Store 事件消费者：把事件总线上的事件持久化到 SQLite（结构化表）+ JSONL（原始流水）。
type Store struct {
	cfg    config.StorageConfig
	bus    *event.Bus
	logger *slog.Logger

	db *sql.DB
	jl *jsonlWriter

	closeOnce sync.Once
	wg        sync.WaitGroup
}

// New 创建存储（自动建目录与表）
func New(cfg config.StorageConfig, bus *event.Bus, logger *slog.Logger) (*Store, error) {
	// 数据目录含明文口令与全部命令记录，权限收紧到仅属主可访问
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}
	s := &Store{cfg: cfg, bus: bus, logger: logger}

	if cfg.UseSQLite() {
		dbPath := filepath.Join(cfg.DataDir, "honeypot.db")
		db, err := sql.Open("sqlite", dbPath)
		if err != nil {
			return nil, fmt.Errorf("open sqlite: %w", err)
		}
		// SQLite 建库文件默认权限过宽（0666&umask），收紧到 0600
		_ = os.Chmod(dbPath, 0o600)
		// 单写者，避免写锁冲突
		db.SetMaxOpenConns(1)
		s.db = db
		if err := s.migrate(); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("migrate sqlite: %w", err)
		}
	}
	if cfg.UseJSONL() {
		s.jl = &jsonlWriter{dir: filepath.Join(cfg.DataDir, "events"), retentionDays: cfg.RetentionDays}
	}
	return s, nil
}

// Run 启动消费循环，阻塞直到 ctx 取消。事件攒批后批量落盘。
func (s *Store) Run(ctx context.Context) {
	s.wg.Add(1)
	defer s.wg.Done()

	ch := s.bus.Subscribe()
	defer s.bus.Unsubscribe(ch)

	var pending []event.Event
	flush := func() {
		if len(pending) == 0 {
			return
		}
		s.flush(pending)
		pending = pending[:0]
	}
	defer flush()

	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()
	cleanupTicker := time.NewTicker(cleanupInterval)
	defer cleanupTicker.Stop()

	for {
		select {
		case ev := <-ch:
			pending = append(pending, ev)
			if len(pending) >= flushBatch {
				flush()
			}
		case <-ticker.C:
			flush()
		case <-cleanupTicker.C:
			s.cleanupOldRows()
		case <-ctx.Done():
			// 兜底处理剩余事件
			for {
				select {
				case ev := <-ch:
					pending = append(pending, ev)
				default:
					flush()
					return
				}
			}
		}
	}
}

// Close 关闭资源：先等消费循环把剩余事件处理完，再关闭底层句柄
func (s *Store) Close() {
	s.closeOnce.Do(func() {
		s.wg.Wait()
		if s.jl != nil {
			_ = s.jl.close()
		}
		if s.db != nil {
			_ = s.db.Close()
		}
	})
}

// flush 批量持久化一批事件：JSONL 逐条 append；SQLite 单事务批量提交。
func (s *Store) flush(events []event.Event) {
	if s.jl != nil {
		for _, ev := range events {
			if err := s.jl.write(ev); err != nil {
				s.logger.Warn("write jsonl failed", "error", err)
			}
		}
	}
	if s.db == nil {
		return
	}
	tx, err := s.db.Begin()
	if err != nil {
		s.logger.Warn("begin sqlite tx failed", "error", err)
		return
	}
	for _, ev := range events {
		switch ev.Type {
		case event.TypeConnectionOpened:
			s.insertConnectionOpened(tx, ev)
		case event.TypeConnectionClosed:
			s.insertConnectionClosed(tx, ev)
		case event.TypeAuthAttempt:
			s.insertAuthAttempt(tx, ev)
		case event.TypeSessionOpened:
			s.insertSessionOpened(tx, ev)
		case event.TypeSessionClosed:
			s.insertSessionClosed(tx, ev)
		case event.TypeCommandExecuted:
			s.insertCommand(tx, ev)
		case event.TypeDownloadAttempt, event.TypeConnectAttempt, event.TypeFileWritten, event.TypeAlert:
			s.insertGeneric(tx, ev)
		}
	}
	if err := tx.Commit(); err != nil {
		s.logger.Warn("commit sqlite tx failed", "error", err)
	}
}

func (s *Store) migrate() error {
	stmts := []string{
		// 写性能优化：关闭每条语句的同步 fsync、设置忙等超时，避免 Windows 上逐条自动提交过慢
		`PRAGMA journal_mode=DELETE`,
		`PRAGMA synchronous=NORMAL`,
		`PRAGMA busy_timeout=5000`,
		`CREATE TABLE IF NOT EXISTS connections (
			id TEXT PRIMARY KEY,
			opened_at TEXT,
			closed_at TEXT,
			source_ip TEXT,
			source_port INTEGER,
			target_port INTEGER,
			client_version TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS auth_attempts (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			connection_id TEXT,
			ts TEXT,
			username TEXT,
			password TEXT,
			method TEXT,
			success INTEGER,
			delay_ms INTEGER
		)`,
		`CREATE TABLE IF NOT EXISTS sessions (
			id TEXT PRIMARY KEY,
			connection_id TEXT,
			channel_type TEXT,
			term TEXT,
			cols INTEGER,
			rows INTEGER,
			opened_at TEXT,
			closed_at TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS commands (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			session_id TEXT,
			ts TEXT,
			command TEXT,
			cwd TEXT,
			exit_code INTEGER,
			duration_ms INTEGER,
			output_preview TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS events (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			type TEXT,
			ts TEXT,
			connection_id TEXT,
			session_id TEXT,
			payload TEXT
		)`,
		`CREATE INDEX IF NOT EXISTS idx_auth_conn ON auth_attempts(connection_id)`,
		`CREATE INDEX IF NOT EXISTS idx_cmd_session ON commands(session_id)`,
		`CREATE INDEX IF NOT EXISTS idx_events_type ON events(type)`,
	}
	for _, stmt := range stmts {
		if _, err := s.db.Exec(stmt); err != nil {
			return err
		}
	}
	return nil
}

// insertGeneric M2 扩展事件（下载/连接/文件写入/告警）统一入 events 表
func (s *Store) insertGeneric(tx *sql.Tx, ev event.Event) {
	payload, err := json.Marshal(ev.Data)
	if err != nil {
		return
	}
	_, _ = tx.Exec(
		`INSERT INTO events (type, ts, connection_id, session_id, payload) VALUES (?, ?, ?, ?, ?)`,
		string(ev.Type), ev.Time.Format(time.RFC3339Nano),
		ev.Data["connection_id"], ev.Data["session_id"], string(payload))
}

func (s *Store) insertConnectionOpened(tx *sql.Tx, ev event.Event) {
	_, _ = tx.Exec(
		`INSERT OR IGNORE INTO connections (id, opened_at, source_ip, source_port, target_port, client_version)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		ev.Data["connection_id"], ev.Time.Format(time.RFC3339Nano),
		ev.Data["source_ip"], ev.Data["source_port"], ev.Data["target_port"],
		ev.Data["client_version"])
}

func (s *Store) insertConnectionClosed(tx *sql.Tx, ev event.Event) {
	_, _ = tx.Exec(
		`UPDATE connections SET closed_at = ?, client_version = COALESCE(NULLIF(?, ''), client_version) WHERE id = ?`,
		ev.Time.Format(time.RFC3339Nano), ev.Data["client_version"], ev.Data["connection_id"])
}

func (s *Store) insertAuthAttempt(tx *sql.Tx, ev event.Event) {
	success := 0
	if b, _ := ev.Data["success"].(bool); b {
		success = 1
	}
	_, _ = tx.Exec(
		`INSERT INTO auth_attempts (connection_id, ts, username, password, method, success, delay_ms)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		ev.Data["connection_id"], ev.Time.Format(time.RFC3339Nano),
		ev.Data["username"], ev.Data["password"], ev.Data["method"],
		success, ev.Data["delay_ms"])
}

func (s *Store) insertSessionOpened(tx *sql.Tx, ev event.Event) {
	_, _ = tx.Exec(
		`INSERT OR IGNORE INTO sessions (id, connection_id, channel_type, term, cols, rows, opened_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		ev.Data["session_id"], ev.Data["connection_id"], ev.Data["channel_type"],
		ev.Data["term"], ev.Data["cols"], ev.Data["rows"],
		ev.Time.Format(time.RFC3339Nano))
}

func (s *Store) insertSessionClosed(tx *sql.Tx, ev event.Event) {
	_, _ = tx.Exec(
		`UPDATE sessions SET closed_at = ? WHERE id = ?`,
		ev.Time.Format(time.RFC3339Nano), ev.Data["session_id"])
}

func (s *Store) insertCommand(tx *sql.Tx, ev event.Event) {
	_, _ = tx.Exec(
		`INSERT INTO commands (session_id, ts, command, cwd, exit_code, duration_ms, output_preview)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		ev.Data["session_id"], ev.Time.Format(time.RFC3339Nano),
		ev.Data["command"], ev.Data["cwd"],
		ev.Data["exit_code"], ev.Data["duration_ms"], ev.Data["output_preview"])
}

// cleanupOldRows 按保留期删除 SQLite 中的旧记录，防止长期运行耗尽磁盘。
// 事件时间戳为 RFC3339Nano 文本，同一时区下字符串序与时间序一致，取
// "YYYY-MM-DDTHH:MM:SS" 前缀做边界（保留期含 cutoff 当天，近似即可）。
func (s *Store) cleanupOldRows() {
	if s.db == nil || s.cfg.RetentionDays <= 0 {
		return
	}
	cutoff := time.Now().AddDate(0, 0, -s.cfg.RetentionDays).Format("2006-01-02T00:00:00")
	for _, q := range []string{
		`DELETE FROM auth_attempts WHERE ts < ?`,
		`DELETE FROM commands WHERE ts < ?`,
		`DELETE FROM events WHERE ts < ?`,
		`DELETE FROM sessions WHERE opened_at < ?`,
		`DELETE FROM connections WHERE opened_at < ?`,
	} {
		if _, err := s.db.Exec(q, cutoff); err != nil {
			s.logger.Warn("cleanup old rows failed", "query", q, "error", err)
		}
	}
}

// --- JSONL 原始事件流水 ---

type jsonlWriter struct {
	dir string
	// retentionDays 保留天数：<=0 表示不清理
	retentionDays int

	mu  sync.Mutex
	f   *os.File
	day string
}

func (w *jsonlWriter) write(ev event.Event) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	day := ev.Time.Format("2006-01-02")
	if w.f == nil || day != w.day {
		if err := w.rotate(day); err != nil {
			return err
		}
	}
	b, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	_, err = w.f.Write(append(b, '\n'))
	return err
}

func (w *jsonlWriter) rotate(day string) error {
	// 原始事件流水含明文口令，目录与文件权限收紧
	if err := os.MkdirAll(w.dir, 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(w.dir, day+".jsonl"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if w.f != nil {
		_ = w.f.Close()
	}
	w.f = f
	w.day = day
	w.cleanup()
	return nil
}

// cleanup 删除超过保留期的过期 JSONL 流水（文件名即日期，字典序即时间序）。
func (w *jsonlWriter) cleanup() {
	if w.retentionDays <= 0 {
		return
	}
	cutoff := time.Now().AddDate(0, 0, -w.retentionDays).Format("2006-01-02")
	entries, err := os.ReadDir(w.dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".jsonl") {
			continue
		}
		day := strings.TrimSuffix(name, ".jsonl")
		if day < cutoff {
			_ = os.Remove(filepath.Join(w.dir, name))
		}
	}
}

func (w *jsonlWriter) close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f != nil {
		err := w.f.Close()
		w.f = nil
		return err
	}
	return nil
}
