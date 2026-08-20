package session

import (
	"log/slog"
	"strings"
	"time"

	"honeypot-go/internal/event"
	"honeypot-go/internal/ident"
	"honeypot-go/internal/shell"
	"honeypot-go/internal/tty"
	"honeypot-go/internal/vfs"
)

// Session 表示一次 SSH 会话通道（exec / shell / subsystem）。
// 持有会话级状态：虚拟 cwd、终端参数、ttyrec 录制器。
type Session struct {
	ID      string
	ConnID  string
	Channel string // exec | shell | subsystem
	Term    string
	Cols    int
	Rows    int

	fs      *vfs.FileSystem
	exec    *shell.Executor
	bus     *event.Bus
	logger  *slog.Logger
	cwd     string
	rec     *tty.Recorder
	started time.Time
	closed  bool
}

// New 创建会话（初始 cwd 为 /root，模拟 root 登录）
func New(connID, channel string, fs *vfs.FileSystem, exec *shell.Executor, bus *event.Bus, logger *slog.Logger) *Session {
	return &Session{
		ID:      ident.New("sess"),
		ConnID:  connID,
		Channel: channel,
		fs:      fs,
		exec:    exec,
		bus:     bus,
		logger:  logger,
		cwd:     "/root",
		started: time.Now(),
	}
}

// Open 发布会话开启事件
func (s *Session) Open() {
	s.bus.Publish(event.New(event.TypeSessionOpened, map[string]any{
		"connection_id": s.ConnID,
		"session_id":    s.ID,
		"channel_type":  s.Channel,
		"term":          s.Term,
		"cols":          s.Cols,
		"rows":          s.Rows,
	}))
}

// SetTerm 设置终端参数
func (s *Session) SetTerm(term string, cols, rows int) {
	s.Term, s.Cols, s.Rows = term, cols, rows
}

// SetRecorder 挂载 ttyrec 录制器
func (s *Session) SetRecorder(rec *tty.Recorder) {
	s.rec = rec
}

// RecordInput 录制客户端按键
func (s *Session) RecordInput(p []byte) {
	if s.rec != nil {
		s.rec.Record(p)
	}
}

// RecordOutput 录制服务端输出
func (s *Session) RecordOutput(p []byte) {
	if s.rec != nil {
		s.rec.Record(p)
	}
}

// Cwd 返回当前虚拟工作目录
func (s *Session) Cwd() string { return s.cwd }

// Prompt 生成 shell 提示符
func (s *Session) Prompt() string {
	host := s.fsHostname()
	dir := s.cwd
	if strings.HasPrefix(dir, "/root") {
		dir = "~" + strings.TrimPrefix(dir, "/root")
	}
	return "root@" + host + ":" + dir + "# "
}

// ExecuteLine 执行一行交互命令，返回输出
func (s *Session) ExecuteLine(raw string) []byte {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	newCwd, res := s.exec.Execute(s.ID, s.cwd, raw)
	s.cwd = newCwd
	return res.Output
}

// Close 发布会话关闭事件
func (s *Session) Close() {
	if s.closed {
		return
	}
	s.closed = true
	s.bus.Publish(event.New(event.TypeSessionClosed, map[string]any{
		"connection_id": s.ConnID,
		"session_id":    s.ID,
		"duration_ms":   time.Since(s.started).Milliseconds(),
	}))
}

func (s *Session) fsHostname() string {
	if b, err := s.fs.ReadFile("/etc/hostname"); err == nil {
		return strings.TrimSpace(string(b))
	}
	return "host"
}
