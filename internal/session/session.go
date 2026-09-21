package session

import (
	"log/slog"
	"path"
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

	user    shell.Identity // 登录身份（SSH 认证用户名解析而来）
	fs      *vfs.FileSystem
	exec    *shell.Executor
	bus     *event.Bus
	logger  *slog.Logger
	cwd     string
	rec     *tty.Recorder
	started time.Time
	closed  bool
}

// New 创建会话：以 SSH 认证时的用户名登录，初始 cwd 为该用户的家目录
// （root 为 /root，其他用户如 /home/ubuntu；家目录不存在时与真实 sshd 一样落在 /）。
func New(connID, channel, username string, fs *vfs.FileSystem, exec *shell.Executor, bus *event.Bus, logger *slog.Logger) *Session {
	s := &Session{
		ID:      ident.New("sess"),
		ConnID:  connID,
		Channel: channel,
		fs:      fs,
		exec:    exec,
		bus:     bus,
		logger:  logger,
		started: time.Now(),
	}
	// 身份存进执行器的会话状态，whoami/id/env/$HOME 等命令据此输出
	s.user = exec.SetUser(s.ID, username)
	s.cwd = "/"
	if fs.IsDir(s.user.Home) {
		s.cwd = s.user.Home
	}
	return s
}

// Username 返回登录用户名（已清洗）
func (s *Session) Username() string { return s.user.Name }

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

// RecordInput 录制客户端按键（原始输入帧，回放时默认不播放，见 tty.Recorder）
func (s *Session) RecordInput(p []byte) {
	if s.rec != nil {
		s.rec.RecordInput(p)
	}
}

// RecordOutput 录制服务端输出（攻击者终端上实际会显示的内容）
func (s *Session) RecordOutput(p []byte) {
	if s.rec != nil {
		s.rec.RecordOutput(p)
	}
}

// Cwd 返回当前虚拟工作目录
func (s *Session) Cwd() string { return s.cwd }

// Prompt 生成 shell 提示符
// 形如 root@host:~# 或 ubuntu@host:~/app$ ；家目录显示为 ~
func (s *Session) Prompt() string {
	return s.user.Name + "@" + s.fsHostname() + ":" + s.promptDir() + s.user.PromptChar() + " "
}

// promptDir 把家目录缩写为 ~（按路径边界匹配，/rootfoo 不会被误缩写）
func (s *Session) promptDir() string {
	home, dir := s.user.Home, s.cwd
	if home == "" || home == "/" {
		return dir
	}
	if dir == home {
		return "~"
	}
	if strings.HasPrefix(dir, home+"/") {
		return "~" + dir[len(home):]
	}
	return dir
}

// ExecuteLine 执行一行交互命令，返回输出
func (s *Session) ExecuteLine(raw string) []byte {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	newCwd, res := s.exec.Execute(s.ID, s.cwd, raw)
	s.cwd = newCwd
	// 实时追加命令历史（↑/↓ 可回看，history 命令可查看）
	s.exec.AddHistory(s.ID, raw)
	return res.Output
}

// History 返回本会话命令历史
func (s *Session) History() []string { return s.exec.History(s.ID) }

// Complete 返回给定前缀（相对 cwd 或绝对路径）下的补全候选。
// 候选上限 24 个，防止超大目录下无界输出。
func (s *Session) Complete(prefix string) []string {
	var dir, base string
	if i := strings.LastIndex(prefix, "/"); i >= 0 {
		dir, base = prefix[:i+1], prefix[i+1:]
	} else {
		base = prefix
	}
	dirPath := dir
	if !strings.HasPrefix(dirPath, "/") {
		dirPath = path.Clean(s.cwd + "/" + dirPath)
	} else {
		dirPath = path.Clean(dirPath)
	}
	infos, err := s.fs.List(dirPath)
	if err != nil {
		return nil
	}
	out := make([]string, 0, 24)
	for _, in := range infos {
		if !strings.HasPrefix(in.Name, base) {
			continue
		}
		name := in.Name
		if in.IsDir {
			name += "/"
		}
		out = append(out, dir+name)
		if len(out) >= 24 {
			break
		}
	}
	return out
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
	// 清理会话级命令状态，防长期运行内存泄漏
	s.exec.RemoveSession(s.ID)
}

func (s *Session) fsHostname() string {
	if b, err := s.fs.ReadFile("/etc/hostname"); err == nil {
		return strings.TrimSpace(string(b))
	}
	return "host"
}
