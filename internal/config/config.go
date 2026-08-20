package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config 全局配置根
type Config struct {
	Server  ServerConfig  `yaml:"server"`
	SSH     SSHConfig     `yaml:"ssh"`
	Auth    AuthConfig    `yaml:"auth"`
	VFS     VFSConfig     `yaml:"vfs"`
	Storage StorageConfig `yaml:"storage"`
	Detect  DetectConfig  `yaml:"detect"`
	Log     LogConfig     `yaml:"log"`
}

// DetectConfig 行为分析：规则引擎 + 风险评分 + 告警
type DetectConfig struct {
	Enabled    bool   `yaml:"enabled"`
	WebhookURL string `yaml:"webhook_url"` // 可选：告警推送到 webhook
}

type ServerConfig struct {
	Listen         []string      `yaml:"listen"`
	MaxConnections int           `yaml:"max_connections"`
	IdleTimeout    time.Duration `yaml:"idle_timeout"`
}

type SSHConfig struct {
	ServerVersion string `yaml:"server_version"`
}

type AuthConfig struct {
	SuccessProbability float64  `yaml:"success_probability"`
	DelayMS            []int    `yaml:"delay_ms"`
	WeakPasswords      []string `yaml:"weak_passwords"`
	// 认证方法开关（默认全开，模拟真实 OpenSSH 行为）
	KeyboardInteractive bool `yaml:"keyboard_interactive"`
	PublicKey           bool `yaml:"publickey"`
	// 允许"探测性登录"：真实服务器若配置了 NOPASSWD 用户会直接放行。
	// 蜜罐中用于制造高价值会话，默认关闭。
	AllowNoAuth bool `yaml:"allow_no_auth"`
}

type VFSConfig struct {
	Hostname string   `yaml:"hostname"`
	Users    []string `yaml:"users"`
}

type StorageConfig struct {
	DataDir string `yaml:"data_dir"`
	Driver  string `yaml:"driver"` // 逗号分隔: sqlite,jsonl
	// RetentionDays 数据保留天数：超过后清理 SQLite 旧记录与过期 JSONL 流水。
	// 0 表示不清理（注意：长期运行可能耗尽磁盘）。
	RetentionDays int `yaml:"retention_days"`
}

type LogConfig struct {
	Level string `yaml:"level"`
}

// Default 返回带默认值的配置
func Default() *Config {
	return &Config{
		Server: ServerConfig{
			Listen:         []string{"0.0.0.0:2222"},
			MaxConnections: 500,
			IdleTimeout:    5 * time.Minute,
		},
		SSH: SSHConfig{
			ServerVersion: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6",
		},
		Auth: AuthConfig{
			SuccessProbability:  0.02,
			DelayMS:             []int{200, 800},
			WeakPasswords:       []string{"root", "admin", "password", "123456"},
			KeyboardInteractive: true,
			PublicKey:           true,
			AllowNoAuth:         false,
		},
		VFS: VFSConfig{
			Hostname: "ubuntu-web-01",
			Users:    []string{"root", "ubuntu"},
		},
		Storage: StorageConfig{
			DataDir:       "data",
			Driver:        "sqlite,jsonl",
			RetentionDays: 30,
		},
		Detect: DetectConfig{
			Enabled:    true,
			WebhookURL: "",
		},
		Log: LogConfig{Level: "info"},
	}
}

// Load 从 YAML 文件加载配置
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}
	cfg := Default()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config file: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) Validate() error {
	if len(c.Server.Listen) == 0 {
		return fmt.Errorf("server.listen: at least one listen address required")
	}
	if c.Server.MaxConnections <= 0 {
		c.Server.MaxConnections = 500
	}
	if c.Server.IdleTimeout <= 0 {
		c.Server.IdleTimeout = 5 * time.Minute
	}
	if c.SSH.ServerVersion == "" {
		c.SSH.ServerVersion = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
	}
	if c.Auth.SuccessProbability < 0 || c.Auth.SuccessProbability > 1 {
		return fmt.Errorf("auth.success_probability must be in [0,1]")
	}
	if len(c.Auth.DelayMS) != 2 || c.Auth.DelayMS[0] < 0 || c.Auth.DelayMS[1] < c.Auth.DelayMS[0] {
		return fmt.Errorf("auth.delay_ms must be [min, max] with max >= min >= 0")
	}
	if !c.Auth.KeyboardInteractive && !c.Auth.PublicKey && c.Auth.SuccessProbability > 0 {
		// yaml 未显式配置（零值 false）时保持默认开启，模拟真实 OpenSSH
		c.Auth.KeyboardInteractive = true
		c.Auth.PublicKey = true
	}
	if c.Storage.DataDir == "" {
		c.Storage.DataDir = "data"
	}
	if c.Storage.RetentionDays < 0 {
		c.Storage.RetentionDays = 0 // 0 = 不清理
	}
	return nil
}

// UseSQLite 是否启用 SQLite 存储
func (c *StorageConfig) UseSQLite() bool {
	return containsDriver(c.Driver, "sqlite")
}

// UseJSONL 是否启用 JSONL 事件流水
func (c *StorageConfig) UseJSONL() bool {
	return containsDriver(c.Driver, "jsonl")
}

func containsDriver(drivers, want string) bool {
	for _, d := range splitComma(drivers) {
		if d == want {
			return true
		}
	}
	return false
}

func splitComma(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
