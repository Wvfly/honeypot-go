//go:build linux
// +build linux

// Linux 下用 exec.Command 重新执行自己，新会话（Setsid）+ stdin/stdout/stderr 指向 /dev/null，
// 父进程立刻 os.Exit，子进程独立成为 init 收养的 daemon。这是 Go 内最干净的 daemon 化方式。
package main

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"
)

func daemonize() (int, error) {
	exe, err := os.Executable()
	if err != nil {
		return 0, err
	}

	// 透传除 -d/--daemon 外的参数；子进程身份用环境变量标记，不污染 args，
	// 否则子进程 flag.Parse 会撞上未注册的 -d-child → os.Exit(2)
	passArgs := make([]string, 0, len(os.Args))
	for _, a := range os.Args[1:] {
		if a == "-d" || a == "--daemon" {
			continue
		}
		passArgs = append(passArgs, a)
	}

	devNull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		return 0, err
	}

	cmd := exec.Command(exe, passArgs...)
	cmd.Stdin = devNull
	cmd.Stdout = devNull
	cmd.Stderr = devNull
	cmd.Env = append(os.Environ(), "ANTI_ATTACK_DAEMON_CHILD=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid: true,
	}

	if err := cmd.Start(); err != nil {
		_ = devNull.Close()
		return 0, err
	}
	// 必须在 Release 前取 Pid：Release 后 cmd.Process 被标为不可用，
	// 不同 Go 版本下结构体字段访问语义略有差异，提前抓快照最稳。
	pid := cmd.Process.Pid
	if pid <= 0 {
		_ = cmd.Process.Release()
		go func() { _ = cmd.Wait() }()
		return 0, fmt.Errorf("invalid child pid: %d", pid)
	}

	// 后台 Wait 子进程，150ms 后看是否还活着。
	// 这比单纯 kill(pid, 0) 更强：如果子进程在 150ms 内 exit（listen 失败 /
	// panic / os.Exit），Wait 会拿到 exit code，父进程能把 exit error 透传出来，
	// 而不是 print 一个假 PID 后走人。
	waitDone := make(chan error, 1)
	go func() { waitDone <- cmd.Wait() }()

	select {
	case err := <-waitDone:
		// 子进程 150ms 内已死，把 exit info 抛给父进程
		return 0, fmt.Errorf("child exited within 150ms: %w", err)
	case <-time.After(150 * time.Millisecond):
		// 子进程还活着，Release 让 init 收养
		_ = cmd.Process.Release()
		return pid, nil
	}
}
