package auth

import (
	"log/slog"
	"math/rand/v2"
	"slices"
	"time"

	"honeypot-go/internal/config"
	"honeypot-go/internal/event"
)

// Authenticator 认证欺骗层：
// - 所有认证尝试（含失败）全部记录为事件，供爆破分析；
// - 命中弱口令库的密码按 success_probability 概率"放行"，制造高价值会话；
// - 通过随机延迟模拟真实密码校验耗时，防止用户名枚举的时间侧信道。
type Authenticator struct {
	cfg    config.AuthConfig
	bus    *event.Bus
	logger *slog.Logger
}

// New 创建认证欺骗器
func New(cfg config.AuthConfig, bus *event.Bus, logger *slog.Logger) *Authenticator {
	return &Authenticator{cfg: cfg, bus: bus, logger: logger}
}

// Check 校验一次认证尝试（password 方法），返回是否放行
func (a *Authenticator) Check(connID, username, password, method string) bool {
	delay := a.cfg.DelayMS[0]
	if r := a.cfg.DelayMS[1] - a.cfg.DelayMS[0]; r > 0 {
		delay += rand.IntN(r + 1)
	}
	if delay > 0 {
		time.Sleep(time.Duration(delay) * time.Millisecond)
	}

	hit := slices.Contains(a.cfg.WeakPasswords, password)
	success := hit && rand.Float64() < a.cfg.SuccessProbability

	a.bus.Publish(event.New(event.TypeAuthAttempt, map[string]any{
		"connection_id": connID,
		"username":      username,
		"password":      password,
		"method":        method,
		"success":       success,
		"delay_ms":      delay,
	}))

	if success {
		a.logger.Info("auth granted",
			"connection_id", connID,
			"username", username,
			"password", password,
		)
	}
	return success
}
