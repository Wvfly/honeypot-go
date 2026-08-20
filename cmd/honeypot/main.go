// honeypot-go：SSH 高交互蜜罐入口。
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"honeypot-go/internal/auth"
	"honeypot-go/internal/config"
	"honeypot-go/internal/detect"
	"honeypot-go/internal/event"
	sshsrv "honeypot-go/internal/ssh"
	"honeypot-go/internal/store"
)

func main() {
	configPath := flag.String("config", "configs/honeypot.yaml", "path to config file")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load config: %v\n", err)
		os.Exit(1)
	}

	logger := newLogger(cfg.Log.Level)
	logger.Info("honeypot starting", "listen", cfg.Server.Listen)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// 事件总线：所有模块解耦的枢纽
	bus := event.NewBus()

	// 存储（SQLite + JSONL 原始流水）
	st, err := store.New(cfg.Storage, bus, logger)
	if err != nil {
		logger.Error("init store failed", "error", err)
		os.Exit(1)
	}
	go st.Run(ctx)

	// 行为分析：规则引擎 + 风险评分 + 告警
	if cfg.Detect.Enabled {
		det := detect.New(cfg.Detect, bus, logger)
		go det.Run(ctx)
	}

	// 认证欺骗层
	authn := auth.New(cfg.Auth, bus, logger)

	// SSH 服务端
	srv, err := sshsrv.New(cfg, bus, authn, logger)
	if err != nil {
		logger.Error("init ssh server failed", "error", err)
		os.Exit(1)
	}

	go func() {
		if err := srv.Run(ctx); err != nil {
			logger.Error("ssh server stopped", "error", err)
			stop()
		}
	}()

	<-ctx.Done()
	logger.Info("shutting down")
	srv.Close()
	st.Close()
	logger.Info("bye")
}

func newLogger(level string) *slog.Logger {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))
}
