// Package view 是调试用工具：自启蜜罐 → 连 SSH → 跑命令 → 抓字节流 → 杀蜜罐。
// 用于本地快速验证 shell/vnet 仿真的终端排版（ONLCR 转换、列对齐等）。
// 用法: go run ./cmd/view
package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	sshAddr  = "127.0.0.1:23222"
	username = "root"
	password = "123456"
)

func dialSSH() (*ssh.Client, error) {
	cfg := &ssh.ClientConfig{
		User:            username,
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	var client *ssh.Client
	var err error
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		client, err = ssh.Dial("tcp", sshAddr, cfg)
		if err == nil {
			return client, nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return nil, fmt.Errorf("ssh dial: %w", err)
}

func run(client *ssh.Client, cmd string) {
	sess, err := client.NewSession()
	if err != nil {
		fmt.Fprintln(os.Stderr, "new session:", err)
		return
	}
	defer sess.Close()
	modes := ssh.TerminalModes{ssh.ECHO: 0}
	// 用一个明显宽的 cols 让客户端报告给服务端，便于观察"宽终端下"是否仍然错位
	if err := sess.RequestPty("xterm", 200, 50, modes); err != nil {
		fmt.Fprintln(os.Stderr, "pty:", err)
	}
	out, err := sess.CombinedOutput(cmd)
	fmt.Printf("\n========= %s =========\n", cmd)
	if err != nil {
		fmt.Fprintln(os.Stderr, "exec err:", err)
	}
	// 用 %q 显示转义字符，能直接看到 \r\n 是否被正确产出
	fmt.Printf("---quoted---\n%q\n", string(out))
	fmt.Printf("---rendered---\n%s", string(out))
}

func startHoneypot() (*exec.Cmd, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	bin := filepath.Join(cwd, "data", "honeypot.exe")
	cfg := filepath.Join(cwd, "data", "test.yaml")
	if _, err := os.Stat(bin); err != nil {
		return nil, fmt.Errorf("missing %s: %w", bin, err)
	}
	cmd := exec.Command(bin, "-config", cfg)
	cmd.Dir = cwd
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	// 等待端口就绪
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", sshAddr, 200*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return cmd, nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	_ = cmd.Process.Kill()
	return nil, errors.New("honeypot did not start in 8s")
}

func main() {
	pid, err := startHoneypot()
	if err != nil {
		fmt.Fprintln(os.Stderr, "start honeypot:", err)
		os.Exit(1)
	}
	defer func() {
		_ = pid.Process.Kill()
		_, _ = pid.Process.Wait()
	}()

	client, err := dialSSH()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer client.Close()

	run(client, "ls -l /")
	run(client, "ifconfig")
	run(client, "uname -a; id; ls -la /root")
}
