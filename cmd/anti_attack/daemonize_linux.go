//go:build linux
// +build linux

// Linux 下用 exec.Command 重新执行自己，新会话（Setsid）+ stdin/stdout 指向 /dev/null，
// stderr 指向 <log>.stderr（保留 panic / runtime fatal error 的现场），
// 父进程等子进程通过就绪管道报告"启动成功"或"失败原因"后再退出，
// 子进程随后由 init 收养，独立成为 daemon。这是 Go 内最干净的 daemon 化方式。
package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

// readyTimeout 是等待 daemon 子进程完成启动（监听成功、pidfile 写好）的上限。
const readyTimeout = 10 * time.Second

// daemonize 以 args 为参数重新执行自己作为 daemon，返回子进程 PID。
// 只有子进程通过就绪管道（fd 3）报告 "OK" 才算成功；子进程报告 "ERR: ..."
// 或在报告前就退出，都会返回带原因的 error，而不是打印一个假 PID。
func daemonize(args []string, stderrPath string) (int, error) {
	exe, err := os.Executable()
	if err != nil {
		return 0, err
	}

	devNull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		return 0, err
	}
	defer devNull.Close()

	// stderr 追加写入：Go 的 panic 堆栈、fatal error 都走 stderr，
	// 写进 /dev/null 的话 daemon 崩了什么线索都没有。
	errf, err := os.OpenFile(stderrPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o644)
	if err != nil {
		return 0, fmt.Errorf("open stderr file: %w", err)
	}
	defer errf.Close()
	fmt.Fprintf(errf, "=== %s daemon starting ===\n", time.Now().Format(time.RFC3339))

	pr, pw, err := os.Pipe()
	if err != nil {
		return 0, err
	}
	defer pr.Close()

	cmd := exec.Command(exe, args...)
	cmd.Stdin = devNull
	cmd.Stdout = devNull
	cmd.Stderr = errf
	cmd.ExtraFiles = []*os.File{pw} // 子进程里的 fd 3
	cmd.Env = append(os.Environ(), envDaemonChild+"=1", envReadyFD+"=3")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}

	if err := cmd.Start(); err != nil {
		_ = pw.Close()
		return 0, err
	}
	// 父进程必须关掉自己这份写端，否则子进程死掉后读端收不到 EOF。
	_ = pw.Close()
	pid := cmd.Process.Pid

	// 成功路径不调用 Release：父进程随后直接退出，子进程自动被 init 收养。
	waitCh := make(chan error, 1)
	go func() { waitCh <- cmd.Wait() }()
	msgCh := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(pr)
		msgCh <- strings.TrimSpace(string(b))
	}()

	var (
		msg     string
		waitErr error
		exited  bool
	)
	select {
	case msg = <-msgCh:
	case waitErr = <-waitCh:
		exited = true
		// 子进程可能临死前刚写完错误信息，给读取协程一点时间
		select {
		case msg = <-msgCh:
		case <-time.After(time.Second):
		}
	case <-time.After(readyTimeout):
		_ = cmd.Process.Kill()
		return 0, fmt.Errorf("等待 daemon 就绪超时（%s），已终止子进程；详情见 %s", readyTimeout, stderrPath)
	}

	switch {
	case msg == "OK" && !exited:
		return pid, nil
	case strings.HasPrefix(msg, "ERR: "):
		return 0, errors.New(strings.TrimPrefix(msg, "ERR: "))
	default:
		// 没收到任何报告管道就断了（panic / 被 kill / 就绪后立刻退出）
		if !exited {
			select {
			case waitErr = <-waitCh:
			case <-time.After(2 * time.Second):
				waitErr = errors.New("管道已关闭但进程仍在运行")
			}
		}
		return 0, fmt.Errorf("daemon 未能正常启动（%v）；详情见 %s", waitErr, stderrPath)
	}
}
