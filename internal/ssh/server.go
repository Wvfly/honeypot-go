// Package sshsrv 基于 golang.org/x/crypto/ssh 封装蜜罐 SSH 服务端。
package sshsrv

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"honeypot-go/internal/auth"
	"honeypot-go/internal/config"
	"honeypot-go/internal/event"
	"honeypot-go/internal/ident"
	"honeypot-go/internal/session"
	"honeypot-go/internal/shell"
	"honeypot-go/internal/tty"
	"honeypot-go/internal/vfs"
)

// nl2crlf 把 LF 转为 CRLF（除非前面已有 CR），用于在写到 SSH channel 前做 ONLCR 转换。
// x/crypto/ssh 不像 OpenSSH sshd 那样在 PTY 模式下自动做 ONLCR，
// 蜜罐 executor 的命令输出用 \n 结尾，Windows Terminal / MobaXterm 等客户端
// 的 PTY 终端在收到裸 \n 时光标只下移一格（不回到行首），下一行从上一行的列位置开始，
// 形成"阶梯状"错位；统一转为 \r\n 即可对齐到行首。
func nl2crlf(b []byte) []byte {
	if !bytes.Contains(b, []byte{'\n'}) {
		return b
	}
	out := make([]byte, 0, len(b)+8)
	for i := 0; i < len(b); i++ {
		c := b[i]
		if c == '\n' && (i == 0 || b[i-1] != '\r') {
			out = append(out, '\r')
		}
		out = append(out, c)
	}
	return out
}

// 防御常量
const (
	// handshakeTimeout 握手超时：攻击者只连不上/握手发一半会永久占住 sem 槽位（slowloris）
	handshakeTimeout = 30 * time.Second
	// maxChannelsPerConn 单连接最多并发 session channel 数
	maxChannelsPerConn = 8
	// maxInteractiveLine 交互 shell 单行输入上限，防超长粘贴撑爆内存
	maxInteractiveLine = 64 << 10 // 64 KiB
)

// Server 蜜罐 SSH 服务端
type Server struct {
	cfg        *config.Config
	bus        *event.Bus
	auth       *auth.Authenticator
	logger     *slog.Logger
	hostSigner ssh.Signer
	sem        chan struct{}

	exec *shell.Executor
	fs   *vfs.FileSystem

	// authLimit IP 级认证限速：防单源高频建连爆破刷资源
	authLimit *authLimiter

	mu        sync.Mutex
	listeners []net.Listener
}

// authLimiter IP 级认证限速：滑动窗口内认证尝试超限即拒绝。
// 蜜罐仍收集全部低频爆破凭据，仅挡住单源高频刷资源（默认 60 次/分钟/IP）。
type authLimiter struct {
	mu   sync.Mutex
	seen map[string][]time.Time // ip -> 窗口内认证尝试时间戳
}

func newAuthLimiter() *authLimiter {
	return &authLimiter{seen: make(map[string][]time.Time)}
}

func (l *authLimiter) allow(ip string) bool {
	const (
		window     = time.Minute
		maxPerIP   = 60
		maxEntries = 65536
	)
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	// 防 map 被海量不同 IP 撑爆：条目超限时整体重置（短暂放开限速，可接受）
	if len(l.seen) >= maxEntries {
		l.seen = make(map[string][]time.Time)
	}
	cut := now.Add(-window)
	ts := l.seen[ip]
	kept := ts[:0]
	for _, t := range ts {
		if t.After(cut) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= maxPerIP {
		l.seen[ip] = kept
		return false
	}
	l.seen[ip] = append(kept, now)
	return true
}

// New 创建服务端：加载/生成主机密钥，准备共享执行器
func New(cfg *config.Config, bus *event.Bus, authn *auth.Authenticator, logger *slog.Logger) (*Server, error) {
	signer, err := loadOrCreateHostKey(cfg.Storage.DataDir, logger)
	if err != nil {
		return nil, fmt.Errorf("host key: %w", err)
	}
	fs := vfs.New(cfg.VFS)
	return &Server{
		cfg:        cfg,
		bus:        bus,
		auth:       authn,
		logger:     logger,
		hostSigner: signer,
		sem:        make(chan struct{}, cfg.Server.MaxConnections),
		exec:       shell.New(fs, bus, cfg.VFS.Hostname, logger),
		fs:         fs,
		authLimit:  newAuthLimiter(),
	}, nil
}

// Run 启动所有监听地址，阻塞直到 ctx 取消
func (s *Server) Run(ctx context.Context) error {
	var wg sync.WaitGroup
	errCh := make(chan error, len(s.cfg.Server.Listen))
	for _, addr := range s.cfg.Server.Listen {
		wg.Add(1)
		go func(a string) {
			defer wg.Done()
			if err := s.listenOne(ctx, a); err != nil {
				errCh <- fmt.Errorf("listen %s: %w", a, err)
			}
		}(addr)
	}
	wg.Wait()
	close(errCh)
	var firstErr error
	for err := range errCh {
		if firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// Close 关闭所有监听器
func (s *Server) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, ln := range s.listeners {
		_ = ln.Close()
	}
}

func (s *Server) listenOne(ctx context.Context, addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.listeners = append(s.listeners, ln)
	s.mu.Unlock()
	s.logger.Info("ssh honeypot listening", "addr", addr)

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		nc, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		select {
		case s.sem <- struct{}{}:
		default:
			// 超出最大并发，直接断开
			s.logger.Warn("connection rejected: max concurrent", "remote", nc.RemoteAddr())
			_ = nc.Close()
			continue
		}
		go func() {
			defer func() { <-s.sem }()
			// 防御：executor/sftp 处理链中任何 panic（含攻击者可控触发的越界）
			// 若放任向上传播会终止整个蜜罐进程（进程级 DoS + 检测断档）。
			// 连接级兜底：recover 后仅断开该连接，其余连接不受影响。
			defer func() {
				if r := recover(); r != nil {
					s.logger.Error("panic in connection handler",
						"remote", nc.RemoteAddr().String(), "panic", r)
				}
			}()
			s.handleConn(nc)
		}()
	}
}

func (s *Server) handleConn(nc net.Conn) {
	defer nc.Close()
	connID := ident.New("conn")

	remote, ok := nc.RemoteAddr().(*net.TCPAddr)
	if !ok {
		remote = &net.TCPAddr{}
	}
	local, _ := nc.LocalAddr().(*net.TCPAddr)

	s.bus.Publish(event.New(event.TypeConnectionOpened, map[string]any{
		"connection_id":  connID,
		"source_ip":      remote.IP.String(),
		"source_port":    remote.Port,
		"target_port":    local.Port,
		"client_version": "",
	}))

	ip := remote.IP.String()
	serverConfig := &ssh.ServerConfig{
		ServerVersion: s.cfg.SSH.ServerVersion,
		MaxAuthTries:  6,
		PasswordCallback: func(cm ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			// IP 级认证限速：防单源高频建连爆破刷资源
			if !s.authLimit.allow(ip) {
				return nil, fmt.Errorf("authentication rate limited")
			}
			if s.auth.Check(connID, cm.User(), string(pass), "password") {
				return &ssh.Permissions{}, nil
			}
			return nil, fmt.Errorf("authentication failed")
		},
	}
	if s.cfg.Auth.KeyboardInteractive {
		serverConfig.KeyboardInteractiveCallback = func(cm ssh.ConnMetadata, challenge ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			if !s.authLimit.allow(ip) {
				return nil, fmt.Errorf("authentication rate limited")
			}
			if s.auth.CheckKeyboardInteractive(connID, cm.User(), challenge) {
				return &ssh.Permissions{}, nil
			}
			return nil, fmt.Errorf("authentication failed")
		}
	}
	if s.cfg.Auth.PublicKey {
		serverConfig.PublicKeyCallback = func(cm ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			s.auth.CheckPublicKey(connID, cm.User(), key)
			return nil, fmt.Errorf("unknown public key")
		}
	}
	if s.cfg.Auth.AllowNoAuth {
		serverConfig.NoClientAuth = true
	}
	serverConfig.AddHostKey(s.hostSigner)

	// 握手超时防御：NewServerConn 本身不设 deadline，攻击者可握手发一半就挂起，
	// 永久占满 sem 槽位拒绝正常访问。设置 deadline 后超时自动断开。
	_ = nc.SetDeadline(time.Now().Add(handshakeTimeout))
	conn, chans, reqs, err := ssh.NewServerConn(nc, serverConfig)
	if err != nil {
		s.logger.Debug("handshake/authentication failed", "connection_id", connID, "remote", nc.RemoteAddr().String(), "error", err)
		s.closeConn(connID, "")
		return
	}
	_ = nc.SetDeadline(time.Time{}) // 清除握手 deadline，避免影响后续 channel 读写

	clientVersion := conn.ClientVersion()
	s.logger.Info("session authenticated",
		"connection_id", connID,
		"user", conn.User(),
		"remote", conn.RemoteAddr().String(),
		"client", string(clientVersion),
	)

	go ssh.DiscardRequests(reqs)

	// 连接级空闲兜底：交互 shell 自带 IdleTimeout，但 SFTP/exec/等待新 channel
	// 等非交互路径没有超时，攻击者认证后挂起可长期占住并发槽位。这里对整条连接
	// 做粗粒度 idle 看门狗：超过 IdleTimeout 无 channel 活动即强制断开。
	idleTimeout := s.cfg.Server.IdleTimeout
	if idleTimeout <= 0 {
		idleTimeout = 5 * time.Minute
	}
	var actMu sync.Mutex
	lastAct := time.Now()
	refresh := func() {
		actMu.Lock()
		lastAct = time.Now()
		actMu.Unlock()
	}
	stopWatch := make(chan struct{})
	go func() {
		t := time.NewTicker(idleTimeout)
		defer t.Stop()
		for {
			select {
			case <-stopWatch:
				return
			case <-t.C:
				actMu.Lock()
				elapsed := time.Since(lastAct)
				actMu.Unlock()
				if elapsed >= idleTimeout {
					s.logger.Debug("connection idle timeout, closing", "connection_id", connID)
					_ = nc.Close()
					return
				}
			}
		}
	}()

	// 单连接 channel 数上限：每个 channel 会占一个 goroutine + ttyrec 文件句柄，
	// 防止一个已认证连接开海量 session channel 耗尽资源。
	chanSem := make(chan struct{}, maxChannelsPerConn)
	for newCh := range chans {
		refresh()
		if newCh.ChannelType() != "session" {
			_ = newCh.Reject(ssh.UnknownChannelType, "unsupported channel type")
			continue
		}
		select {
		case chanSem <- struct{}{}:
		default:
			_ = newCh.Reject(ssh.ResourceShortage, "too many concurrent channels")
			continue
		}
		ch, requests, err := newCh.Accept()
		if err != nil {
			<-chanSem
			s.logger.Debug("accept channel failed", "error", err)
			continue
		}
		go func() {
			defer func() { <-chanSem }()
			// handleSession 运行在独立 goroutine（handleConn 的 recover 覆盖不到），
			// 此处单独兜底：exec/shell/sftp 子系统的 panic 只杀该 channel 不杀进程
			defer func() {
				if r := recover(); r != nil {
					s.logger.Error("panic in session handler",
						"connection_id", connID, "panic", r)
				}
			}()
			s.handleSession(conn, connID, ch, requests, refresh)
		}()
	}

	close(stopWatch)
	_ = conn.Wait()
	s.closeConn(connID, string(clientVersion))
}

func (s *Server) closeConn(connID, clientVersion string) {
	s.bus.Publish(event.New(event.TypeConnectionClosed, map[string]any{
		"connection_id":  connID,
		"client_version": clientVersion,
	}))
}

// handleSession 处理 session channel 上的请求（pty-req / exec / shell / subsystem...）
func (s *Server) handleSession(conn *ssh.ServerConn, connID string, ch ssh.Channel, reqs <-chan *ssh.Request, refresh func()) {
	defer ch.Close()

	var (
		sess    *session.Session
		recFile *os.File
	)

	createSession := func(chType string) {
		if sess != nil {
			return
		}
		sess = session.New(connID, chType, s.fs, s.exec, s.bus, s.logger)
		// ttyrec 录制：含全部命令内容，目录/文件权限收紧
		dir := filepath.Join(s.cfg.Storage.DataDir, "recordings")
		if err := os.MkdirAll(dir, 0o700); err == nil {
			if f, err := os.OpenFile(filepath.Join(dir, sess.ID+".ttyrec"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600); err == nil {
				recFile = f
				sess.SetRecorder(tty.NewRecorder(f))
			}
		}
		sess.Open()
	}

	closeSession := func() {
		if sess != nil {
			sess.Close()
			sess = nil
		}
		if recFile != nil {
			_ = recFile.Close()
			recFile = nil
		}
	}

	for req := range reqs {
		refresh() // 任何请求都视为连接活动，刷新连接级 idle
		switch req.Type {
		case "pty-req":
			var p struct {
				Term          string
				Cols, Rows    uint32
				Width, Height uint32
				Modes         string
			}
			if err := ssh.Unmarshal(req.Payload, &p); err == nil {
				createSession("shell")
				sess.SetTerm(p.Term, int(p.Cols), int(p.Rows))
			}
			_ = req.Reply(sess != nil, nil)

		case "window-change":
			var p struct {
				Cols, Rows    uint32
				Width, Height uint32
			}
			if err := ssh.Unmarshal(req.Payload, &p); err == nil && sess != nil {
				sess.SetTerm(sess.Term, int(p.Cols), int(p.Rows))
			}
			_ = req.Reply(false, nil)

		case "env":
			_ = req.Reply(false, nil)

		case "exec":
			var p struct{ Command string }
			if err := ssh.Unmarshal(req.Payload, &p); err != nil {
				_ = req.Reply(false, nil)
				continue
			}
			_ = req.Reply(true, nil)
			createSession("exec")
			_, res := s.exec.Execute(sess.ID, sess.Cwd(), p.Command)
			if len(res.Output) > 0 {
				out := nl2crlf(res.Output)
				_, _ = ch.Write(out)
				sess.RecordOutput(out)
			}
			closeSession()
			_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{uint32(res.Code)}))
			return

		case "shell":
			_ = req.Reply(true, nil)
			createSession("shell")
			s.runInteractiveShell(ch, sess, refresh)
			closeSession()
			_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
			return

		case "subsystem":
			name := ""
			if len(req.Payload) >= 4 {
				name = string(req.Payload[4:])
			}
			if name != "sftp" {
				_ = req.Reply(false, nil)
				return
			}
			_ = req.Reply(true, nil)
			createSession("subsystem")
			handler := &vfsHandler{fs: s.fs, bus: s.bus, sessionID: sess.ID}
			srv := sftp.NewRequestServer(ch, sftp.Handlers{
				FileGet:  handler,
				FilePut:  handler,
				FileCmd:  handler,
				FileList: handler,
			})
			_ = srv.Serve()
			closeSession()
			return

		default:
			_ = req.Reply(false, nil)
		}
	}
	closeSession()
}

// runInteractiveShell 交互式 shell 循环：回显按键、逐行执行命令。
// 通过 select + 定时器实现真正的 IdleTimeout：认证后不发数据的连接（slowloris）
// 到期自动断开，不再永久占住并发槽位。
func (s *Server) runInteractiveShell(ch ssh.Channel, sess *session.Session, refresh func()) {
	timeout := s.cfg.Server.IdleTimeout
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}

	prompt := sess.Prompt()
	promptOut := nl2crlf([]byte(prompt))
	_, _ = ch.Write(promptOut)
	sess.RecordOutput(promptOut)

	// 读 goroutine：ch.Read 阻塞，读结果经 dataCh 交给主循环（配合 idle 定时器）。
	// done 通道保证函数退出后读 goroutine 不再阻塞在 dataCh 发送上。
	type readResult struct {
		data []byte
		err  error
	}
	done := make(chan struct{})
	defer close(done)
	dataCh := make(chan readResult, 1)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := ch.Read(buf)
			if n > 0 {
				cp := make([]byte, n)
				copy(cp, buf[:n])
				select {
				case dataCh <- readResult{data: cp}:
				case <-done:
					return
				}
			}
			if err != nil {
				select {
				case dataCh <- readResult{err: err}:
				default:
				}
				return
			}
		}
	}()

	idle := time.NewTimer(timeout)
	defer idle.Stop()

	line := make([]byte, 0, 256)
	process := func(data []byte) bool {
		refresh() // 有输入活动，刷新连接级 idle
		sess.RecordInput(data)
		for _, b := range data {
			switch b {
			case '\r', '\n':
				_, _ = ch.Write([]byte("\r\n"))
				sess.RecordOutput([]byte("\r\n"))
				cmd := string(line)
				line = line[:0]
				if cmd == "exit" || cmd == "logout" {
					return false
				}
				out := sess.ExecuteLine(cmd)
				if len(out) > 0 {
					out = nl2crlf(out)
					_, _ = ch.Write(out)
					sess.RecordOutput(out)
				}
				promptOut := nl2crlf([]byte(sess.Prompt()))
				_, _ = ch.Write(promptOut)
				sess.RecordOutput(promptOut)

			case 0x03: // Ctrl-C
				line = line[:0]
				_, _ = ch.Write([]byte("^C\r\n"))
				sess.RecordOutput([]byte("^C\r\n"))
				_, _ = ch.Write([]byte(sess.Prompt()))
				sess.RecordOutput([]byte(sess.Prompt()))

			case 0x04: // Ctrl-D
				_, _ = ch.Write([]byte("logout\r\n"))
				return false

			case 0x7f, 0x08: // Backspace
				if len(line) > 0 {
					line = line[:len(line)-1]
					_, _ = ch.Write([]byte("\b \b"))
					sess.RecordOutput([]byte("\b \b"))
				}

			default:
				if b >= 0x20 || b == '\t' {
					// 超长行截断，防止无回车粘贴无限增长占用内存
					if len(line) < maxInteractiveLine {
						line = append(line, b)
						_, _ = ch.Write([]byte{b})
						sess.RecordOutput([]byte{b})
					}
				}
			}
		}
		return true
	}

	for {
		select {
		case r := <-dataCh:
			if r.err != nil {
				return
			}
			if !process(r.data) {
				return
			}
			// 有输入活动，重置空闲计时器
			if !idle.Stop() {
				select {
				case <-idle.C:
				default:
				}
			}
			idle.Reset(timeout)
		case <-idle.C:
			s.logger.Debug("interactive shell idle timeout, closing", "session_id", sess.ID)
			return
		}
	}
}

// loadOrCreateHostKey 从 data_dir/host_key 加载或生成 ed25519 主机密钥
func loadOrCreateHostKey(dataDir string, logger *slog.Logger) (ssh.Signer, error) {
	path := filepath.Join(dataDir, "host_key")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return nil, err
	}
	if b, err := os.ReadFile(path); err == nil {
		return ssh.ParsePrivateKey(b)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, err
	}
	// 持久化主机密钥，保持指纹稳定
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		logger.Warn("persist host key failed", "error", err)
	}
	return signer, nil
}
