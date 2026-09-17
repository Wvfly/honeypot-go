//go:build linux
// +build linux

// Linux 下用 exec.Command 重新执行自己，新会话（Setsid）+ stdin/stdout/stderr 指向 /dev/null，
// 父进程立刻 os.Exit，子进程独立成为 init 收养的 daemon。这是 Go 内最干净的 daemon 化方式。
package main

import (
	"os"
	"os/exec"
	"syscall"
)

func daemonize() (int, error) {
	exe, err := os.Executable()
	if err != nil {
		return 0, err
	}

	// 透传除 -d/--daemon/-d-child 外的参数，避免父死循环子、子死循环孙
	passArgs := make([]string, 0, len(os.Args))
	for _, a := range os.Args[1:] {
		if a == "-d" || a == "--daemon" || a == "-d-child" {
			continue
		}
		passArgs = append(passArgs, a)
	}
	passArgs = append(passArgs, "-d-child")

	devNull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		return 0, err
	}

	cmd := exec.Command(exe, passArgs...)
	cmd.Stdin = devNull
	cmd.Stdout = devNull
	cmd.Stderr = devNull
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid: true,
	}

	if err := cmd.Start(); err != nil {
		_ = devNull.Close()
		return 0, err
	}
	// 释放 Process 句柄，让 init 收养；后台 goroutine 仅用于 reaper 清理
	_ = cmd.Process.Release()
	go func() { _ = cmd.Wait() }()
	return cmd.Process.Pid, nil
}
