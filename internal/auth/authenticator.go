package auth

import (
	"log/slog"
	"math/rand/v2"
	"slices"
	"time"

	"golang.org/x/crypto/ssh"

	"honeypot-go/internal/config"
	"honeypot-go/internal/event"
)

// Authenticator 认证欺骗层：
// - 所有认证尝试（含失败）全部记录为事件，供爆破分析；
// - 命中弱口令库的密码按 success_probability 概率"放行"，制造高价值会话；
// - 通过随机延迟模拟真实密码校验耗时，防止用户名枚举的时间侧信道；
// - 支持 password / keyboard-interactive / publickey 三种方法（与真实 OpenSSH 行为对齐）。
type Authenticator struct {
	cfg    config.AuthConfig
	bus    *event.Bus
	logger *slog.Logger
}

// New 创建认证欺骗器
func New(cfg config.AuthConfig, bus *event.Bus, logger *slog.Logger) *Authenticator {
	return &Authenticator{cfg: cfg, bus: bus, logger: logger}
}

// Check 校验一次 password 认证尝试，返回是否放行
func (a *Authenticator) Check(connID, username, password, method string) bool {
	return a.checkPassword(connID, username, password, method)
}

// CheckKeyboardInteractive 模拟 Linux PAM 风格多轮问答：
// 第一轮 "Password:"，未命中则追加一轮 "Current password:" 再失败即拒绝。
func (a *Authenticator) CheckKeyboardInteractive(connID, username string, challenge ssh.KeyboardInteractiveChallenge) bool {
	answers, err := challenge("", "Password authentication", []string{"Password: "}, []bool{false})
	if err != nil || len(answers) == 0 || answers[0] == "" {
		a.record(connID, username, "", "keyboard-interactive", false, 0, "")
		return false
	}
	if a.checkPassword(connID, username, answers[0], "keyboard-interactive") {
		return true
	}
	// PAM 风格第二轮（Current password），模拟 expired/challenge 场景
	answers, err = challenge("", "Password authentication", []string{"Current password: "}, []bool{false})
	if err != nil || len(answers) == 0 {
		return false
	}
	return a.checkPassword(connID, username, answers[0], "keyboard-interactive")
}

// CheckPublicKey 解析并记录公钥指纹，一律拒绝（蜜罐无 authorized_keys）。
// 攻击者投放的恶意公钥指纹会入库，可与持久化事件关联。
func (a *Authenticator) CheckPublicKey(connID, username string, key ssh.PublicKey) bool {
	fp := ssh.FingerprintSHA256(key)
	a.record(connID, username, "", "publickey", false, 0, fp)
	a.logger.Info("publickey auth attempted",
		"connection_id", connID,
		"username", username,
		"pubkey_type", key.Type(),
		"fingerprint", fp,
	)
	return false
}

// checkPassword 核心：随机延迟 + 弱口令命中 + 概率放行，统一记录事件
func (a *Authenticator) checkPassword(connID, username, password, method string) bool {
	delay := a.cfg.DelayMS[0]
	if r := a.cfg.DelayMS[1] - a.cfg.DelayMS[0]; r > 0 {
		delay += rand.IntN(r + 1)
	}
	if delay > 0 {
		time.Sleep(time.Duration(delay) * time.Millisecond)
	}

	hit := slices.Contains(a.cfg.WeakPasswords, password)
	success := hit && rand.Float64() < a.cfg.SuccessProbability
	a.record(connID, username, password, method, success, delay, "")

	if success {
		a.logger.Info("auth granted",
			"connection_id", connID,
			"username", username,
			"password", password,
			"method", method,
		)
	}
	return success
}

func (a *Authenticator) record(connID, username, password, method string, success bool, delay int, pubkeyFP string) {
	a.bus.Publish(event.New(event.TypeAuthAttempt, map[string]any{
		"connection_id": connID,
		"username":      username,
		"password":      password,
		"method":        method,
		"success":       success,
		"delay_ms":      delay,
		"pubkey_fp":     pubkeyFP,
	}))
}
