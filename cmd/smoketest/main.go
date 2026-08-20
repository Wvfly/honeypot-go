// smoketest 冒烟测试客户端：验证蜜罐认证欺骗、命令执行、会话闭环。
// 用法: go run ./cmd/smoketest [-addr 127.0.0.1:23222]
package main

import (
	"flag"
	"fmt"
	"os"

	"golang.org/x/crypto/ssh"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:23222", "honeypot address")
	flag.Parse()

	// 1) 弱口令登录 + 执行命令
	cmd := "uname -a; id; ls -la /root; cat /etc/passwd; cd /tmp && pwd; whoami"
	if out, err := runSession(*addr, "root", "123456", cmd); err != nil {
		fmt.Println("[FAIL] session error:", err)
		os.Exit(1)
	} else {
		fmt.Println("===== command output =====")
		fmt.Print(string(out))
		fmt.Println("==========================")
		fmt.Println("[OK] weak-password login + command execution")
	}

	// 2) 错误密码必须认证失败
	if out, err := runSession(*addr, "root", "wrongpass", "id"); err == nil {
		fmt.Println("[FAIL] expected auth failure, got output:", string(out))
		os.Exit(1)
	} else {
		fmt.Println("[OK] wrong password rejected:", err)
	}

	// 3) 未知命令应返回 127 / command not found
	if out, err := runSession(*addr, "root", "123456", "nosuchcmd"); err != nil {
		fmt.Println("[FAIL] command error:", err)
		os.Exit(1)
	} else {
		fmt.Print(string(out))
		fmt.Println("[OK] unknown command handled")
	}

	fmt.Println("[PASS] smoke test done")
}

func runSession(addr, user, pass, command string) ([]byte, error) {
	config := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(pass)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * 1e9,
	}
	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return nil, fmt.Errorf("dial+auth: %w", err)
	}
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("new session: %w", err)
	}
	defer sess.Close()

	out, err := sess.CombinedOutput(command)
	if err != nil && err.(*ssh.ExitError).ExitStatus() != 127 {
		return out, err
	}
	return out, nil
}
