package vfs

import (
	"fmt"
	"hash/fnv"
	fsys "io/fs"
	"path"
	"sort"
	"strings"
	"sync"
	"time"

	"honeypot-go/internal/config"
)

// node 虚拟文件系统节点
type node struct {
	name     string
	isDir    bool
	perm     string // 类似 "-rw-r--r--" 的权限串
	owner    string
	group    string
	size     int64
	mtime    time.Time
	content  []byte
	children map[string]*node
}

// FileSystem 内存虚拟文件系统（M1：只读快照 + 基本目录导航）
type FileSystem struct {
	mu       sync.RWMutex
	root     *node
	hostname string
}

// New 创建并预置一个逼真的 Linux 根文件系统
func New(cfg config.VFSConfig) *FileSystem {
	fs := &FileSystem{
		hostname: cfg.Hostname,
		root:     &node{name: "/", isDir: true, perm: "drwxr-xr-x", owner: "root", group: "root", children: map[string]*node{}},
	}
	fs.bootstrap(cfg.Users)
	return fs
}

func (fs *FileSystem) addFile(path, perm, owner, group string, content []byte) {
	parts := splitPath(path)
	dir := fs.root
	for _, p := range parts[:len(parts)-1] {
		if d, ok := dir.children[p]; ok && d.isDir {
			dir = d
			continue
		}
		d := &node{name: p, isDir: true, perm: "drwxr-xr-x", owner: "root", group: "root", mtime: fakeMtime("/" + strings.Join(parts[:len(parts)-1], "/")), children: map[string]*node{}}
		dir.children[p] = d
		dir = d
	}
	dir.children[parts[len(parts)-1]] = &node{
		name:    parts[len(parts)-1],
		perm:    perm,
		owner:   owner,
		group:   group,
		size:    int64(len(content)),
		mtime:   fakeMtime(path),
		content: content,
	}
}

func (fs *FileSystem) addDir(path, perm, owner, group string) {
	parts := splitPath(path)
	dir := fs.root
	for _, p := range parts {
		if d, ok := dir.children[p]; ok && d.isDir {
			dir = d
			continue
		}
		d := &node{name: p, isDir: true, perm: perm, owner: owner, group: group, mtime: fakeMtime("/" + strings.Join(parts, "/")), children: map[string]*node{}}
		dir.children[p] = d
		dir = d
	}
}

// fakeMtime 基于路径生成确定性的"历史"修改时间（1~90 天前 + 小时偏移），
// 避免所有文件 mtime 都是同一时刻（真实系统不一致）。
func fakeMtime(path string) time.Time {
	h := fnv.New32a()
	h.Write([]byte(path))
	sum := h.Sum32()
	days := int(sum % 90)
	hours := int((sum >> 8) % 24)
	mins := int((sum >> 16) % 60)
	return time.Now().AddDate(0, 0, -days).Add(-time.Duration(hours)*time.Hour - time.Duration(mins)*time.Minute)
}

func (fs *FileSystem) bootstrap(users []string) {
	host := fs.hostname

	// /etc
	passwd := "root:x:0:0:root:/root:/bin/bash\n"
	shadow := "root:$6$rounds=656000$ZyHdQ8m4tZ8mK0n$:19800:0:99999:7:::\n"
	uid := 1000
	for _, u := range users {
		if u == "root" {
			continue
		}
		home := "/home/" + u
		if u == "www-data" {
			home = "/var/www"
		}
		passwd += fmt.Sprintf("%s:x:%d:%d:%s:%s:/bin/bash\n", u, uid, uid, u, home)
		uid++
	}
	passwd += "sshd:x:65534:65534:sshd:/var/run/sshd:/usr/sbin/nologin\n"
	fs.addFile("/etc/passwd", "-rw-r--r--", "root", "root", []byte(passwd))
	fs.addFile("/etc/shadow", "-rw-------", "root", "shadow", []byte(shadow))
	fs.addFile("/etc/hostname", "-rw-r--r--", "root", "root", []byte(host+"\n"))
	fs.addFile("/etc/hosts", "-rw-r--r--", "root", "root",
		[]byte("127.0.0.1\tlocalhost\n127.0.1.1\t"+host+"\n"))
	fs.addFile("/etc/os-release", "-rw-r--r--", "root", "root",
		[]byte("NAME=\"Ubuntu\"\nVERSION=\"22.04.3 LTS (Jammy Jellyfish)\"\nID=ubuntu\nVERSION_ID=\"22.04\"\n"))
	fs.addFile("/etc/motd", "-rw-r--r--", "root", "root",
		[]byte("Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)\n"))
	fs.addFile("/var/log/auth.log", "-rw-r-----", "syslog", "adm",
		[]byte("Aug 18 02:11:03 "+host+" sshd[2312]: Accepted publickey for ubuntu from 10.0.2.15\nAug 19 07:42:11 "+host+" sshd[2319]: Failed password for invalid user admin from 203.0.113.4 port 53321 ssh2\n"))

	// --- P2 扩充：系统目录 / 日志 / 配置 / 家目录 / 应用 ---

	// 基础系统目录
	fs.addDir("/bin", "drwxr-xr-x", "root", "root")
	fs.addDir("/sbin", "drwxr-xr-x", "root", "root")
	fs.addDir("/usr", "drwxr-xr-x", "root", "root")
	fs.addDir("/usr/bin", "drwxr-xr-x", "root", "root")
	fs.addDir("/usr/sbin", "drwxr-xr-x", "root", "root")
	fs.addDir("/usr/local", "drwxr-xr-x", "root", "root")
	fs.addDir("/usr/local/bin", "drwxr-xr-x", "root", "root")
	fs.addDir("/lib", "drwxr-xr-x", "root", "root")
	fs.addDir("/boot", "drwxr-xr-x", "root", "root")
	fs.addDir("/mnt", "drwxr-xr-x", "root", "root")
	fs.addDir("/media", "drwxr-xr-x", "root", "root")
	fs.addDir("/var", "drwxr-xr-x", "root", "root")
	fs.addDir("/var/backups", "drwxr-xr-x", "root", "root")
	fs.addDir("/var/run", "drwxr-xr-x", "root", "root")

	// /proc（动态内容经 procContent 生成，节点须存在才能命中）
	fs.addDir("/proc", "dr-xr-xr-x", "root", "root")
	fs.addDir("/proc/net", "dr-xr-xr-x", "root", "root")
	fs.addDir("/proc/self", "dr-xr-xr-x", "root", "root")
	fs.addFile("/proc/version", "-r--r--r--", "root", "root", nil)
	fs.addFile("/proc/cpuinfo", "-r--r--r--", "root", "root", nil)
	fs.addFile("/proc/meminfo", "-r--r--r--", "root", "root", nil)
	fs.addFile("/proc/uptime", "-r--r--r--", "root", "root", nil)
	fs.addFile("/proc/loadavg", "-r--r--r--", "root", "root", nil)
	fs.addFile("/proc/stat", "-r--r--r--", "root", "root", nil)
	fs.addFile("/proc/self/status", "-r--r--r--", "root", "root", nil)
	fs.addFile("/proc/self/cmdline", "-r--r--r--", "root", "root", nil)
	fs.addFile("/proc/net/tcp", "-r--r--r--", "root", "root", nil)
	fs.addFile("/proc/net/udp", "-r--r--r--", "root", "root", nil)
	fs.addFile("/proc/net/arp", "-r--r--r--", "root", "root", nil)

	// 更多 /etc 配置
	fs.addDir("/etc/ssh", "drwxr-xr-x", "root", "root")
	fs.addFile("/etc/ssh/sshd_config", "-rw-r--r--", "root", "root",
		[]byte("Port 22\nPermitRootLogin yes\nPasswordAuthentication yes\nPubkeyAuthentication yes\nChallengeResponseAuthentication no\nUsePAM yes\nX11Forwarding yes\n"))
	fs.addDir("/etc/nginx", "drwxr-xr-x", "root", "root")
	fs.addDir("/etc/nginx/sites-enabled", "drwxr-xr-x", "root", "root")
	fs.addFile("/etc/nginx/nginx.conf", "-rw-r--r--", "root", "root",
		[]byte("user www-data;\nworker_processes auto;\nevents { worker_connections 768; }\nhttp {\n\tsendfile on;\n\tinclude /etc/nginx/sites-enabled/*;\n}\n"))
	fs.addFile("/etc/nginx/sites-enabled/default", "-rw-r--r--", "root", "root",
		[]byte("server {\n\tlisten 80 default_server;\n\troot /var/www;\n\tindex index.html;\n}\n"))
	fs.addDir("/etc/ufw", "drwxr-xr-x", "root", "root")
	fs.addFile("/etc/ufw/ufw.conf", "-rw-r--r--", "root", "root",
		[]byte("ENABLED=yes\nDEFAULT_INPUT_POLICY=\"DROP\"\nDEFAULT_OUTPUT_POLICY=\"ACCEPT\"\n"))
	fs.addFile("/etc/resolv.conf", "-rw-r--r--", "root", "root",
		[]byte("nameserver 8.8.8.8\nnameserver 8.8.4.4\n"))
	fs.addFile("/etc/issue", "-rw-r--r--", "root", "root",
		[]byte("Ubuntu 22.04.3 LTS \\n \\l\n"))
	fs.addFile("/etc/hosts.allow", "-rw-r--r--", "root", "root",
		[]byte("# /etc/hosts.allow\nsshd: 10.0.0.0/8\n"))
	fs.addFile("/etc/hosts.deny", "-rw-r--r--", "root", "root",
		[]byte("# /etc/hosts.deny\n"))
	fs.addFile("/etc/group", "-rw-r--r--", "root", "root",
		[]byte("root:x:0:\ndaemon:x:1:\nbin:x:2:\nsys:x:3:\nadm:x:4:syslog\nwww-data:x:33:\nssh:x:110:\nnogroup:x:65534:\n"))
	fs.addFile("/etc/crontab", "-rw-r--r--", "root", "root",
		[]byte("SHELL=/bin/sh\nPATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n17 *\t* * *\troot\tcd / && run-parts --report /etc/cron.hourly\n25 6\t* * *\troot\ttest -x /usr/sbin/anacron || run-parts --report /etc/cron.daily\n"))
	fs.addDir("/var/spool/cron", "drwxr-xr-x", "root", "root")
	fs.addDir("/var/spool/cron/crontabs", "drwx------", "root", "crontab")
	fs.addFile("/var/spool/cron/crontabs/root", "-rw-------", "root", "crontab",
		[]byte("# Edit this file to introduce tasks to be run by cron.\n*/5 * * * * /usr/local/bin/backup.sh >/dev/null 2>&1\n"))

	// /var/log 更多日志
	fs.addDir("/var/log", "drwxr-xr-x", "root", "syslog")
	fs.addFile("/var/log/syslog", "-rw-r-----", "syslog", "adm",
		[]byte("Aug 19 02:03:55 "+host+" systemd[1]: Started Session 22 of user root.\nAug 19 02:11:00 "+host+" sshd[2312]: Server listening on 0.0.0.0 port 22.\n"))
	fs.addFile("/var/log/kern.log", "-rw-r-----", "syslog", "adm",
		[]byte("Aug 18 22:41:12 "+host+" kernel: [ 1234.567890] eth0: link up, 1000Mbps, full-duplex\n"))
	fs.addFile("/var/log/dpkg.log", "-rw-r-----", "root", "adm",
		[]byte("2026-06-15 09:12:03 install nginx:amd64 1.18.0-6ubuntu14.4\n2026-06-15 09:12:08 status installed nginx:amd64 1.18.0-6ubuntu14.4\n"))

	// /root 家目录
	fs.addDir("/root", "drwx------", "root", "root")
	fs.addDir("/root/.ssh", "drwx------", "root", "root")
	fs.addFile("/root/.ssh/authorized_keys", "-rw-------", "root", "root",
		[]byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILpVN7mA6QvO0vKsQ1Yh+9nWl9sXm2OaJt2pKzVq1Q== attacker@vm\n"))
	fs.addFile("/root/.bash_history", "-rw-------", "root", "root",
		[]byte("ls -la\ncd /var/www\napt update\nwhoami\n"))
	fs.addFile("/root/.bashrc", "-rw-r--r--", "root", "root",
		[]byte("# ~/.bashrc\nalias ll='ls -alF'\nalias ls='ls --color=auto'\nexport HISTSIZE=2000\n"))
	fs.addFile("/root/.profile", "-rw-r--r--", "root", "root",
		[]byte("# ~/.profile\nif [ -n \"$BASH_VERSION\" ]; then\n\tif [ -f \"$HOME/.bashrc\" ]; then\n\t\t. \"$HOME/.bashrc\"\n\tfi\nfi\n"))
	fs.addFile("/root/.wget-hsts", "-rw-------", "root", "root",
		[]byte("example.com:0:0\n"))

	// /home
	fs.addDir("/home", "drwxr-xr-x", "root", "root")
	for _, u := range users {
		if u == "root" || u == "www-data" {
			continue
		}
		fs.addDir("/home/"+u, "drwxr-xr-x", u, u)
		fs.addDir("/home/"+u+"/.ssh", "drwx------", u, u)
		fs.addFile("/home/"+u+"/.ssh/authorized_keys", "-rw-------", u, u,
			[]byte("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7vJ1QcXj6fN9kLw+4lWc/UbYVt0Y0pX5U7D0sJ2qWqY7fQJbT+6y7v0y+q9Xq1j0zWU0pKk== "+u+"@localhost\n"))
		fs.addFile("/home/"+u+"/.bashrc", "-rw-r--r--", u, u, []byte("# ~/.bashrc\n"))
		fs.addFile("/home/"+u+"/.profile", "-rw-r--r--", u, u, []byte("# ~/.profile\n"))
		fs.addFile("/home/"+u+"/.wget-hsts", "-rw-------", u, u, []byte(""))
	}
	fs.addDir("/home/ubuntu", "drwxr-xr-x", "ubuntu", "ubuntu")
	fs.addDir("/home/ubuntu/.ssh", "drwx------", "ubuntu", "ubuntu")
	fs.addFile("/home/ubuntu/.ssh/authorized_keys", "-rw-------", "ubuntu", "ubuntu",
		[]byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK5yEoPz2mz0lOqrGb5cMZ4h/8dQ5vDqV5fM+Xf6VbA== admin@laptop\n"))
	fs.addFile("/home/ubuntu/.profile", "-rw-r--r--", "ubuntu", "ubuntu", []byte("# ~/.profile\n"))
	fs.addFile("/home/ubuntu/README.txt", "-rw-r--r--", "ubuntu", "ubuntu",
		[]byte("Server migration notes:\n- Nginx config in /etc/nginx\n- MySQL on 127.0.0.1:3306\n"))

	// 应用与入侵入口目录
	fs.addDir("/var/www", "drwxr-xr-x", "root", "root")
	fs.addDir("/var/www/html", "drwxr-xr-x", "www-data", "www-data")
	fs.addFile("/var/www/html/index.html", "-rw-r--r--", "www-data", "www-data",
		[]byte("<html><body><h1>Welcome to Ubuntu!</h1><p>nginx web server is running.</p></body></html>\n"))
	fs.addDir("/opt", "drwxr-xr-x", "root", "root")
	fs.addFile("/opt/README.md", "-rw-r--r--", "root", "root",
		[]byte("Deployment notes\n=================\n- apps: /srv/*.sh\n- logs: /var/log\n"))
	fs.addDir("/srv", "drwxr-xr-x", "root", "root")
	fs.addFile("/srv/backup.sh", "-rwxr-xr-x", "root", "root",
		[]byte("#!/bin/bash\n# Nightly backup to NAS\ntar czf /var/backups/www-$(date +%F).tar.gz /var/www\n"))
	fs.addDir("/tmp", "drwxrwxrwt", "root", "root")
	fs.addDir("/var/tmp", "drwxrwxrwt", "root", "root")
	fs.addDir("/dev/shm", "drwxrwxrwt", "root", "root")
}

// splitPath 把绝对路径拆成各层名字
func splitPath(path string) []string {
	clean := strings.Trim(path, "/")
	if clean == "" {
		return nil
	}
	return strings.Split(clean, "/")
}

// walkPath 沿路径逐段导航，支持 "." 与 ".." 语义：
// "." 停留当前节点，".." 向父级回溯（根目录的 ".." 仍为根目录，与真实系统一致）。
// 返回最终节点；任意段不存在返回 ok=false。
func (fs *FileSystem) walkPath(path string) (*node, bool) {
	parts := splitPath(path)
	cur := fs.root
	var stack []*node // 记录经过的父节点，供 ".." 回溯
	for _, p := range parts {
		switch p {
		case ".", "":
			continue
		case "..":
			if len(stack) > 0 {
				cur = stack[len(stack)-1]
				stack = stack[:len(stack)-1]
			}
			continue
		}
		next, ok := cur.children[p]
		if !ok {
			return nil, false
		}
		stack = append(stack, cur)
		cur = next
	}
	return cur, true
}

func (fs *FileSystem) resolve(path string) (*node, bool) {
	return fs.walkPath(path)
}

// Resolve 返回路径对应节点（对外只读视图）
func (fs *FileSystem) Resolve(path string) (info FileInfo, ok bool) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	n, found := fs.resolve(path)
	if !found {
		return FileInfo{}, false
	}
	return n.info(), true
}

// List 列出目录内容，返回排序后的条目
func (fs *FileSystem) List(path string) ([]FileInfo, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	n, ok := fs.resolve(path)
	if !ok {
		return nil, fmt.Errorf("no such file or directory")
	}
	if !n.isDir {
		return nil, fmt.Errorf("not a directory")
	}
	out := make([]FileInfo, 0, len(n.children)+2)
	for _, c := range n.children {
		out = append(out, c.info())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// ReadDir2 返回目录条目（io/fs.DirEntry），供 shell 通配符展开
func (fs *FileSystem) ReadDir2(path string) ([]fsys.DirEntry, error) {
	infos, err := fs.List(path)
	if err != nil {
		return nil, err
	}
	out := make([]fsys.DirEntry, 0, len(infos))
	for _, fi := range infos {
		out = append(out, vfsDirEntry{name: fi.Name, isDir: fi.IsDir})
	}
	return out, nil
}

// vfsDirEntry 实现 io/fs.DirEntry
type vfsDirEntry struct {
	name  string
	isDir bool
}

func (d vfsDirEntry) Name() string { return d.name }
func (d vfsDirEntry) IsDir() bool  { return d.isDir }
func (d vfsDirEntry) Type() fsys.FileMode {
	if d.isDir {
		return fsys.ModeDir
	}
	return 0
}
func (d vfsDirEntry) Info() (fsys.FileInfo, error) {
	return nil, fmt.Errorf("Info not supported")
}

// ReadFile 读取文件内容（/proc 下动态生成）
func (fs *FileSystem) ReadFile(path string) ([]byte, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	n, ok := fs.resolve(path)
	if !ok {
		return nil, fmt.Errorf("no such file or directory")
	}
	if n.isDir {
		return nil, fmt.Errorf("is a directory")
	}
	if content := fs.procContent(path); content != nil {
		return content, nil
	}
	return n.content, nil
}

// IsDir 判断路径是否为目录
func (fs *FileSystem) IsDir(path string) bool {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	n, ok := fs.resolve(path)
	return ok && n.isDir
}

// maxFileSize 单文件写入大小上限：防止恶意超大写入撑爆内存（与 sftp 上传上限一致）
const maxFileSize = 64 << 20 // 64 MiB

// WriteFile 覆盖写入（父目录必须存在），M2 用于 echo > / wget 落盘
func (fs *FileSystem) WriteFile(path string, data []byte) error {
	return fs.write(path, data, false)
}

// AppendFile 追加写入，用于 echo >>
func (fs *FileSystem) AppendFile(path string, data []byte) error {
	return fs.write(path, data, true)
}

func (fs *FileSystem) write(path string, data []byte, appendMode bool) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return fs.lockedWrite(path, data, appendMode)
}

// lockedWrite 无锁写实现：调用方须持有 fs.mu
func (fs *FileSystem) lockedWrite(path string, data []byte, appendMode bool) error {
	parts := splitPath(path)
	if len(parts) == 0 {
		return fmt.Errorf("invalid path")
	}
	dir := fs.root
	var stack []*node // 记录父节点，供 ".." 回溯
	for _, p := range parts[:len(parts)-1] {
		switch p {
		case ".", "":
			continue
		case "..":
			if len(stack) > 0 {
				dir = stack[len(stack)-1]
				stack = stack[:len(stack)-1]
			}
			continue
		}
		next, ok := dir.children[p]
		if !ok || !next.isDir {
			return fmt.Errorf("no such directory")
		}
		stack = append(stack, dir)
		dir = next
	}
	// 权限校验：目标所在目录需有写权限（owner/group/other 任一写位）
	if !permWritable(dir.perm) {
		return fmt.Errorf("permission denied: directory %q is read-only", dir.name)
	}
	name := parts[len(parts)-1]
	if name == "." || name == ".." {
		return fmt.Errorf("is a directory")
	}
	n, exists := dir.children[name]
	if !exists {
		n = &node{name: name, perm: "-rw-r--r--", owner: "root", group: "root", mtime: time.Now()}
		dir.children[name] = n
	} else if n.isDir {
		return fmt.Errorf("is a directory")
	} else if !permWritable(n.perm) {
		// 已存在文件：owner 无写位则拒绝覆盖，防止篡改只读系统文件污染环境
		return fmt.Errorf("permission denied: file %q is read-only", path)
	}
	newSize := int64(len(data))
	if appendMode {
		newSize += int64(len(n.content))
	}
	if newSize > maxFileSize {
		return fmt.Errorf("file %q exceeds max size %d", path, maxFileSize)
	}
	if appendMode {
		n.content = append(n.content, data...)
	} else {
		n.content = append([]byte(nil), data...)
	}
	n.size = int64(len(n.content))
	n.mtime = time.Now()
	return nil
}

// permWritable 判断权限串（如 "-rw-r--r--" / "drwxrwxrwt"）是否带写位。
// 索引 2/5/8 分别为 owner/group/other 的写权限。
func permWritable(perm string) bool {
	if len(perm) < 9 {
		return true // 非法/未知权限串按可写处理，避免误拒绝
	}
	return perm[2] == 'w' || perm[5] == 'w' || perm[8] == 'w'
}

// locateNode 解析路径为 (父目录节点, 末段名称)，支持 "."/".." 语义。
// 调用方须持有 fs.mu（或 RLock 足够，因为只读）。
func (fs *FileSystem) locateNode(p string) (parent *node, name string, ok bool) {
	parts := splitPath(p)
	if len(parts) == 0 {
		return nil, "", false
	}
	dir := fs.root
	var stack []*node
	for _, seg := range parts[:len(parts)-1] {
		switch seg {
		case ".", "":
			continue
		case "..":
			if len(stack) > 0 {
				dir = stack[len(stack)-1]
				stack = stack[:len(stack)-1]
			}
			continue
		}
		next, ok := dir.children[seg]
		if !ok || !next.isDir {
			return nil, "", false
		}
		stack = append(stack, dir)
		dir = next
	}
	name = parts[len(parts)-1]
	if name == "." || name == ".." {
		return nil, "", false
	}
	return dir, name, true
}

// Mkdir 创建目录（含中间目录）。目标所在目录需可写。返回已存在错误。
func (fs *FileSystem) Mkdir(p, perm, owner, group string) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	parts := splitPath(p)
	if len(parts) == 0 {
		return fmt.Errorf("invalid path")
	}
	dir := fs.root
	var stack []*node
	for _, seg := range parts {
		switch seg {
		case ".", "":
			continue
		case "..":
			if len(stack) > 0 {
				dir = stack[len(stack)-1]
				stack = stack[:len(stack)-1]
			}
			continue
		}
		if existing, ok := dir.children[seg]; ok && existing.isDir {
			dir = existing
			stack = append(stack, dir)
			continue
		}
		if _, ok := dir.children[seg]; ok {
			return fmt.Errorf("cannot create directory %q: File exists", seg)
		}
		if !permWritable(dir.perm) {
			return fmt.Errorf("permission denied: directory %q is read-only", dir.name)
		}
		d := &node{name: seg, isDir: true, perm: "drwxr-xr-x", owner: "root", group: "root", mtime: time.Now(), children: map[string]*node{}}
		dir.children[seg] = d
		stack = append(stack, dir)
		dir = d
	}
	// 最终目录应用指定权限/属主
	dir.perm = perm
	dir.owner = owner
	dir.group = group
	return nil
}

// Remove 删除文件或空目录；非空目录返回错误（rm -r 语义由 RemoveAll 提供）。
func (fs *FileSystem) Remove(p string) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	parent, name, ok := fs.locateNode(p)
	if !ok {
		return fmt.Errorf("no such file or directory")
	}
	n, exists := parent.children[name]
	if !exists {
		return fmt.Errorf("no such file or directory")
	}
	if n.isDir && len(n.children) > 0 {
		return fmt.Errorf("directory not empty")
	}
	if !permWritable(parent.perm) {
		return fmt.Errorf("permission denied: directory %q is read-only", parent.name)
	}
	delete(parent.children, name)
	return nil
}

// RemoveAll 递归删除文件或目录（rm -rf 语义）。
func (fs *FileSystem) RemoveAll(p string) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	parent, name, ok := fs.locateNode(p)
	if !ok {
		return fmt.Errorf("no such file or directory")
	}
	if _, exists := parent.children[name]; !exists {
		return fmt.Errorf("no such file or directory")
	}
	if !permWritable(parent.perm) {
		return fmt.Errorf("permission denied: directory %q is read-only", parent.name)
	}
	delete(parent.children, name)
	return nil
}

// Rename 重命名/移动（跨目录）。源与目标父目录均需可写；不覆盖已存在目标。
func (fs *FileSystem) Rename(oldPath, newPath string) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	srcParent, srcName, ok := fs.locateNode(oldPath)
	if !ok {
		return fmt.Errorf("no such file or directory")
	}
	src, exists := srcParent.children[srcName]
	if !exists {
		return fmt.Errorf("no such file or directory")
	}
	dstParent, dstName, ok := fs.locateNode(newPath)
	if !ok {
		return fmt.Errorf("no such file or directory")
	}
	if !permWritable(srcParent.perm) || !permWritable(dstParent.perm) {
		return fmt.Errorf("permission denied")
	}
	if _, exists := dstParent.children[dstName]; exists {
		return fmt.Errorf("cannot overwrite existing file or directory")
	}
	delete(srcParent.children, srcName)
	src.name = dstName
	dstParent.children[dstName] = src
	return nil
}

// Copy 复制文件（目标为完整路径），受 maxFileSize 限制；不覆盖已存在目标。
func (fs *FileSystem) Copy(srcPath, dstPath string) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	src, ok := fs.resolve(srcPath)
	if !ok || src.isDir {
		return fmt.Errorf("no such file or directory")
	}
	dstParent, dstName, ok := fs.locateNode(dstPath)
	if !ok {
		return fmt.Errorf("no such file or directory")
	}
	if !permWritable(dstParent.perm) {
		return fmt.Errorf("permission denied: directory %q is read-only", dstParent.name)
	}
	if _, exists := dstParent.children[dstName]; exists {
		return fmt.Errorf("cannot overwrite existing file")
	}
	cp := &node{
		name:    dstName,
		perm:    src.perm,
		owner:   src.owner,
		group:   src.group,
		size:    src.size,
		mtime:   time.Now(),
		content: append([]byte(nil), src.content...),
	}
	dstParent.children[dstName] = cp
	return nil
}

// Chmod 修改权限位（保留类型位）。
func (fs *FileSystem) Chmod(p, perm string) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	n, ok := fs.resolve(p)
	if !ok {
		return fmt.Errorf("no such file or directory")
	}
	if len(perm) < 9 {
		return fmt.Errorf("invalid mode")
	}
	n.perm = string(n.perm[0]) + perm[1:]
	return nil
}

// Chown 修改属主/组（空串表示不变）。
func (fs *FileSystem) Chown(p, owner, group string) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	n, ok := fs.resolve(p)
	if !ok {
		return fmt.Errorf("no such file or directory")
	}
	if owner != "" {
		n.owner = owner
	}
	if group != "" {
		n.group = group
	}
	return nil
}

// Touch 创建空文件（若不存在）或仅更新 mtime。
func (fs *FileSystem) Touch(p string) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if n, ok := fs.resolve(p); ok {
		if n.isDir {
			return fmt.Errorf("is a directory")
		}
		n.mtime = time.Now()
		return nil
	}
	return fs.lockedWrite(p, nil, false)
}

// maxWalkNodes 单次遍历上限：防 find/du 在超大目录树上无界遍历占用 CPU
const maxWalkNodes = 20000

// Walk 先序遍历以 root 为根的子树（不含 root 自身），对每个节点调用 fn(relPath, FileInfo)。
// relPath 为相对 root 的路径；fn 返回 false 终止遍历。返回遍历是否被提前终止。
func (fs *FileSystem) Walk(root string, fn func(string, FileInfo) bool) bool {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	n, ok := fs.resolve(root)
	if !ok || !n.isDir {
		return false
	}
	count := 0
	var walk func(dir *node, rel string) bool
	walk = func(dir *node, rel string) bool {
		count++
		if count > maxWalkNodes {
			return false
		}
		names := make([]string, 0, len(dir.children))
		for name := range dir.children {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			child := dir.children[name]
			childRel := name
			if rel != "" {
				childRel = rel + "/" + name
			}
			if !fn(childRel, child.info()) {
				return false
			}
			if child.isDir && !walk(child, childRel) {
				return false
			}
		}
		return true
	}
	return walk(n, "")
}

// Glob 通配符匹配（支持末层 * ? []），返回绝对路径列表，供 shell 字段展开
func (fs *FileSystem) Glob(pattern string) []string {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	idx := strings.LastIndex(pattern, "/")
	dirPart, basePart := "/", pattern
	if idx >= 0 {
		dirPart, basePart = pattern[:idx], pattern[idx+1:]
	}
	hasMeta := strings.ContainsAny(basePart, "*?[")
	if !hasMeta {
		if _, ok := fs.resolve(pattern); ok {
			return []string{pattern}
		}
		return nil
	}
	dirNode, ok := fs.resolve(dirPart)
	if !ok || !dirNode.isDir {
		return nil
	}
	var out []string
	for name, child := range dirNode.children {
		if ok, _ := path.Match(basePart, name); ok {
			p := strings.TrimSuffix(dirPart, "/") + "/" + name
			if child.isDir {
				p += "/"
			}
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}

// procContent 动态生成 /proc 下内容（bootstrap 中需存在对应节点才能命中）
func (fs *FileSystem) procContent(path string) []byte {
	switch path {
	case "/proc/version":
		return []byte("Linux version 5.15.0-91-generic (buildd@lcy02-amd64-046) #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023\n")
	case "/proc/cpuinfo":
		return []byte("processor\t: 0\nvendor_id\t: GenuineIntel\nmodel name\t: Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz\ncpu MHz\t\t: 2399.996\n")
	case "/proc/meminfo":
		return []byte("MemTotal:       16383952 kB\nMemFree:         4123456 kB\nMemAvailable:   11472544 kB\n")
	case "/proc/uptime":
		return []byte("1234567.89 9876543.21\n")
	case "/proc/loadavg":
		return []byte("0.00 0.01 0.05 1/312 403\n")
	case "/proc/stat":
		return []byte("cpu  123456 789 65432 987654321 1234 0 5678 0 0 0\n" +
			"cpu0 123456 789 65432 987654321 1234 0 5678 0 0 0\n" +
			"intr 234567890 45 89 0 0 0 0 0 0 0\n" +
			"ctxt 1234567890\nbtime 1700000000\nprocesses 5432\nprocs_running 1\nprocs_blocked 0\n")
	case "/proc/self/status":
		// PID 与 ps 输出联动（bash pid=403, sshd@pts/0 pid=402）
		return []byte("Name:\tbash\nUmask:\t0022\nState:\tS (sleeping)\nTgid:\t403\nNgid:\t0\nPid:\t403\nPPid:\t402\n" +
			"TracerPid:\t0\nUid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\nFDSize:\t256\nGroups:\t0 \n" +
			"VmPeak:\t  121200 kB\nVmSize:\t  121200 kB\nRssAnon:\t    2656 kB\nRssFile:\t    1632 kB\nThreads:\t1\n")
	case "/proc/self/cmdline":
		return []byte("-bash\x00")
	case "/proc/net/tcp":
		// 0x0016=22, 0x0CEA=3306（与 netstat 输出联动）
		return []byte("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
			"   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 27396 1 ffff880000000000 100 0 0 10 0\n" +
			"   1: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 27402 1 ffff880000000000 100 0 0 10 0\n" +
			"   2: 0100007F:0CEA 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 29172 1 ffff880000000000 100 0 0 10 0\n")
	case "/proc/net/udp":
		return []byte("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
			"   0: 00000000:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 26140 2 ffff880000000000 100 0 0 10 0\n")
	case "/proc/net/arp":
		return []byte("IP address       HW type     Flags       HW address            Mask     Device\n" +
			"10.0.2.2         0x1         0x2         52:54:00:12:35:02     *        eth0\n" +
			"10.0.2.15        0x1         0x2         08:00:27:ab:cd:ef     *        eth0\n")
	}
	return nil
}

// FileInfo 只读文件信息视图
type FileInfo struct {
	Name  string
	IsDir bool
	Perm  string
	Owner string
	Group string
	Size  int64
	Mtime time.Time
}

func (n *node) info() FileInfo {
	return FileInfo{Name: n.name, IsDir: n.isDir, Perm: n.perm, Owner: n.owner, Group: n.group, Size: n.size, Mtime: n.mtime}
}
