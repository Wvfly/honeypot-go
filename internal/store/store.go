package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "modernc.org/sqlite"

	"honeypot-go/internal/config"
	"honeypot-go/internal/event"
)

// Store 事件消费者：把事件总线上的事件持久化到 SQLite（结构化表）+ JSONL（原始流水）。
type Store struct {
	cfg    config.StorageConfig
	bus    *event.Bus
	logger *slog.Logger

	db *sql.DB
	jl *jsonlWriter

	ch        chan event.Event
	closeOnce sync.Once
	wg        sync.WaitGroup
}

// New 创建存储（自动建目录与表）
func New(cfg config.StorageConfig, bus *event.Bus, logger *slog.Logger) (*Store, error) {
	if err := os.MkdirAll(cfg.DataDir, 0o755); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}
	s := &Store{cfg: cfg, bus: bus, logger: logger, ch: make(chan event.Event, 512)}

	if cfg.UseSQLite() {
		db, err := sql.Open("sqlite", filepath.Join(cfg.DataDir, "honeypot.db"))
		if err != nil {
			return nil, fmt.Errorf("open sqlite: %w", err)
		}
		// 单写者，避免写锁冲突
		db.SetMaxOpenConns(1)
		s.db = db
		if err := s.migrate(); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("migrate sqlite: %w", err)
		}
	}
	if cfg.UseJSONL() {
		s.jl = &jsonlWriter{dir: filepath.Join(cfg.DataDir, "events")}
	}
	return s, nil
}

// Run 启动消费循环，阻塞直到 ctx 取消
func (s *Store) Run(ctx context.Context) {
	s.wg.Add(1)
	defer s.wg.Done()

	ch := s.bus.Subscribe()
	defer s.bus.Unsubscribe(ch)

	for {
		select {
		case ev := <-ch:
			s.handle(ev)
		case <-ctx.Done():
			// 兜底处理剩余事件
			for {
				select {
				case ev := <-ch:
					s.handle(ev)
				default:
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

func (s *Store) handle(ev event.Event) {
	if s.jl != nil {
		if err := s.jl.write(ev); err != nil {
			s.logger.Warn("write jsonl failed", "error", err)
		}
	}
	if s.db == nil {
		return
	}
	switch ev.Type {
	case event.TypeConnectionOpened:
		s.insertConnectionOpened(ev)
	case event.TypeConnectionClosed:
		s.insertConnectionClosed(ev)
	case event.TypeAuthAttempt:
		s.insertAuthAttempt(ev)
	case event.TypeSessionOpened:
		s.insertSessionOpened(ev)
	case event.TypeSessionClosed:
		s.insertSessionClosed(ev)
	case event.TypeCommandExecuted:
		s.insertCommand(ev)
	}
}

func (s *Store) migrate() error {
	stmts := []string{
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
		`CREATE INDEX IF NOT EXISTS idx_auth_conn ON auth_attempts(connection_id)`,
		`CREATE INDEX IF NOT EXISTS idx_cmd_session ON commands(session_id)`,
	}
	for _, stmt := range stmts {
		if _, err := s.db.Exec(stmt); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) insertConnectionOpened(ev event.Event) {
	_, _ = s.db.Exec(
		`INSERT OR IGNORE INTO connections (id, opened_at, source_ip, source_port, target_port, client_version)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		ev.Data["connection_id"], ev.Time.Format(time.RFC3339Nano),
		ev.Data["source_ip"], ev.Data["source_port"], ev.Data["target_port"],
		ev.Data["client_version"])
}

func (s *Store) insertConnectionClosed(ev event.Event) {
	_, _ = s.db.Exec(
		`UPDATE connections SET closed_at = ?, client_version = COALESCE(NULLIF(?, ''), client_version) WHERE id = ?`,
		ev.Time.Format(time.RFC3339Nano), ev.Data["client_version"], ev.Data["connection_id"])
}

func (s *Store) insertAuthAttempt(ev event.Event) {
	success := 0
	if b, _ := ev.Data["success"].(bool); b {
		success = 1
	}
	_, _ = s.db.Exec(
		`INSERT INTO auth_attempts (connection_id, ts, username, password, method, success, delay_ms)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		ev.Data["connection_id"], ev.Time.Format(time.RFC3339Nano),
		ev.Data["username"], ev.Data["password"], ev.Data["method"],
		success, ev.Data["delay_ms"])
}

func (s *Store) insertSessionOpened(ev event.Event) {
	_, _ = s.db.Exec(
		`INSERT OR IGNORE INTO sessions (id, connection_id, channel_type, term, cols, rows, opened_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		ev.Data["session_id"], ev.Data["connection_id"], ev.Data["channel_type"],
		ev.Data["term"], ev.Data["cols"], ev.Data["rows"],
		ev.Time.Format(time.RFC3339Nano))
}

func (s *Store) insertSessionClosed(ev event.Event) {
	_, _ = s.db.Exec(
		`UPDATE sessions SET closed_at = ? WHERE id = ?`,
		ev.Time.Format(time.RFC3339Nano), ev.Data["session_id"])
}

func (s *Store) insertCommand(ev event.Event) {
	_, _ = s.db.Exec(
		`INSERT INTO commands (session_id, ts, command, cwd, exit_code, duration_ms, output_preview)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		ev.Data["session_id"], ev.Time.Format(time.RFC3339Nano),
		ev.Data["command"], ev.Data["cwd"],
		ev.Data["exit_code"], ev.Data["duration_ms"], ev.Data["output_preview"])
}

// --- JSONL 原始事件流水 ---

type jsonlWriter struct {
	dir string

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
	if err := os.MkdirAll(w.dir, 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(w.dir, day+".jsonl"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	if w.f != nil {
		_ = w.f.Close()
	}
	w.f = f
	w.day = day
	return nil
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
