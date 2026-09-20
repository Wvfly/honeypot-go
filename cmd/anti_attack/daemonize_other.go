//go:build !linux
// +build !linux

package main

import "errors"

func daemonize(args []string, stderrPath string) (int, error) {
	return 0, errors.New("-d / --daemon 仅在 Linux 上支持；Windows 下请用 nssm / sc.exe CreateService 把 anti_attack 注册为服务")
}
