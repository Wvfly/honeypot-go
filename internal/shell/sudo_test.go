package shell

import (
	"log/slog"
	"strings"
	"testing"

	"honeypot-go/internal/config"
	"honeypot-go/internal/event"
	"honeypot-go/internal/vfs"
)

func newTestExecutor(t *testing.T) *Executor {
	t.Helper()
	fs := vfs.New(config.VFSConfig{Hostname: "ubuntu-web-01", Users: []string{"root"}})
	bus := event.NewBus()
	return New(fs, bus, "ubuntu-web-01", slog.Default())
}

// stripLeadingSudo 基础剥离
func TestStripLeadingSudo(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"sudo ls", "ls"},
		{"sudo sudo ls", "ls"},
		{"sudo sudo sudo id", "id"},
		{"ls", "ls"},
		{"sudo -l", "sudo -l"},
		{"sudo -u root id", "sudo -u root id"},
		{"sudosomething ls", "sudosomething ls"},
		{"sudo", ""},
	}
	for _, c := range cases {
		if got := stripLeadingSudo(c.in); got != c.want {
			t.Errorf("stripLeadingSudo(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// sudo sudo ... ls（深度 1000）不会爆栈，且最终输出正常
func TestSudoDeepNesting(t *testing.T) {
	e := newTestExecutor(t)
	line := strings.Repeat("sudo ", 1000) + "echo ok"
	_, res := e.Execute("s1", "/root", line)
	if !strings.Contains(string(res.Output), "ok") {
		t.Fatalf("deep sudo chain output lost: %q", res.Output)
	}
}

// 命令替换内嵌 sudo 也受 maxCmdSubstDepth 限制，不会无限递归
func TestSudoCmdSubstDepth(t *testing.T) {
	e := newTestExecutor(t)
	// 构造足够深但不爆内存的嵌套：$(sudo $(sudo ... echo ok))
	line := strings.Repeat("sudo $(", 200) + "echo ok" + strings.Repeat(")", 200)
	_, res := e.Execute("s2", "/root", line)
	// 不应 panic，结果可为空或含 ok
	_ = res
}

// 普通 sudo 行为不被破坏
func TestSudoNormal(t *testing.T) {
	e := newTestExecutor(t)
	_, res := e.Execute("s3", "/root", "sudo id")
	if !strings.Contains(string(res.Output), "uid=0(root)") {
		t.Fatalf("sudo id output unexpected: %q", res.Output)
	}
}
