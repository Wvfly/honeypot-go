// Package sshsrv 基于 golang.org/x/crypto/ssh 封装蜜罐 SSH 服务端。
package sshsrv

import (
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

	mu        sync.Mutex
	listeners []net.Listener
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

	serverConfig := &ssh.ServerConfig{
		ServerVersion: s.cfg.SSH.ServerVersion,
		MaxAuthTries:  6,
		PasswordCallback: func(cm ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if s.auth.Check(connID, cm.User(), string(pass), "password") {
				return &ssh.Permissions{}, nil
			}
			return nil, fmt.Errorf("authentication failed")
		},
	}
	serverConfig.AddHostKey(s.hostSigner)

	conn, chans, reqs, err := ssh.NewServerConn(nc, serverConfig)
	if err != nil {
		s.logger.Debug("handshake/authentication failed", "connection_id", connID, "remote", nc.RemoteAddr().String(), "error", err)
		s.closeConn(connID, "")
		return
	}

	clientVersion := conn.ClientVersion()
	s.logger.Info("session authenticated",
		"connection_id", connID,
		"user", conn.User(),
		"remote", conn.RemoteAddr().String(),
		"client", string(clientVersion),
	)

	go ssh.DiscardRequests(reqs)

	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			_ = newCh.Reject(ssh.UnknownChannelType, "unsupported channel type")
			continue
		}
		ch, requests, err := newCh.Accept()
		if err != nil {
			s.logger.Debug("accept channel failed", "error", err)
			continue
		}
		go s.handleSession(conn, connID, ch, requests)
	}

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
func (s *Server) handleSession(conn *ssh.ServerConn, connID string, ch ssh.Channel, reqs <-chan *ssh.Request) {
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
		// ttyrec 录制
		dir := filepath.Join(s.cfg.Storage.DataDir, "recordings")
		if err := os.MkdirAll(dir, 0o755); err == nil {
			if f, err := os.Create(filepath.Join(dir, sess.ID+".ttyrec")); err == nil {
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
				_, _ = ch.Write(res.Output)
				sess.RecordOutput(res.Output)
			}
			closeSession()
			_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{uint32(res.Code)}))
			return

		case "shell":
			_ = req.Reply(true, nil)
			createSession("shell")
			s.runInteractiveShell(ch, sess)
			closeSession()
			_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
			return

		case "subsystem":
			// M2 支持 sftp；当前拒绝
			_ = req.Reply(false, nil)
			_, _ = ch.Write([]byte("subsystem request failed on channel 0\r\n"))
			return

		default:
			_ = req.Reply(false, nil)
		}
	}
	closeSession()
}

// runInteractiveShell 交互式 shell 循环：回显按键、逐行执行命令
func (s *Server) runInteractiveShell(ch ssh.Channel, sess *session.Session) {
	prompt := sess.Prompt()
	_, _ = ch.Write([]byte(prompt))
	sess.RecordOutput([]byte(prompt))

	line := make([]byte, 0, 256)
	buf := make([]byte, 4096)
	for {
		n, err := ch.Read(buf)
		if err != nil {
			return
		}
		data := buf[:n]
		sess.RecordInput(data)

		for _, b := range data {
			switch b {
			case '\r', '\n':
				_, _ = ch.Write([]byte("\r\n"))
				sess.RecordOutput([]byte("\r\n"))
				cmd := string(line)
				line = line[:0]
				if cmd == "exit" || cmd == "logout" {
					return
				}
				out := sess.ExecuteLine(cmd)
				if len(out) > 0 {
					_, _ = ch.Write(out)
					sess.RecordOutput(out)
				}
				_, _ = ch.Write([]byte(sess.Prompt()))
				sess.RecordOutput([]byte(sess.Prompt()))

			case 0x03: // Ctrl-C
				line = line[:0]
				_, _ = ch.Write([]byte("^C\r\n"))
				sess.RecordOutput([]byte("^C\r\n"))
				_, _ = ch.Write([]byte(sess.Prompt()))
				sess.RecordOutput([]byte(sess.Prompt()))

			case 0x04: // Ctrl-D
				_, _ = ch.Write([]byte("logout\r\n"))
				return

			case 0x7f, 0x08: // Backspace
				if len(line) > 0 {
					line = line[:len(line)-1]
					_, _ = ch.Write([]byte("\b \b"))
					sess.RecordOutput([]byte("\b \b"))
				}

			default:
				if b >= 0x20 || b == '\t' {
					line = append(line, b)
					_, _ = ch.Write([]byte{b})
					sess.RecordOutput([]byte{b})
				}
			}
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
