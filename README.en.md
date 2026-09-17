# honeypot-go

![Go](https://img.shields.io/badge/Go-1.22+-00ADD8?logo=go&logoColor=white)
![Status](https://img.shields.io/badge/Status-M2%20Release-blue)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-4EAA25)
![Build](https://img.shields.io/badge/Build-Passing-brightgreen)
[中文文档](README.md) | [English](README.en.md)

A high-interaction SSH honeypot framework written in Go. It lures, records, and analyzes an attacker's full kill chain — **scan → brute force → login → recon → payload delivery → lateral movement** — at minimal real-world risk.

Every command, file, and network behavior is **emulated in user space**, so the honeypot itself can never be "compromised". Outbound traffic is disabled by default, so it cannot be abused as a pivot.

> Warning: Deploy this tool ONLY on assets and networks you are authorized to test (security research / red team exercises). Deploying a honeypot without authorization may violate the law.

---

## Features

**Implemented (M1)**

- Multi-port listening (default `2222` / `22222`), spoofed OpenSSH 8.9 server version
- Auth deception: weak-password dictionary + probabilistic admission + randomized check delay (anti user-enumeration timing side channel)
- Interactive shell emulation: `cd / ls / cat / uname / id / ps / whoami / echo / pwd` builtins & system commands, with `&& / | / ;` composition
- In-memory virtual file system: realistic Linux root snapshot (`/etc/passwd`, `/proc`, `/home/*` dynamic content)
- Full event pipeline: connection / auth / session / command, persisted to SQLite (structured) + JSONL (raw stream)
- ttyrec session recording: every keystroke and terminal output, replayable frame by frame
- Graceful shutdown: drains pending events before closing, zero data loss

**Implemented (M2)**

- Auth method expansion: `keyboard-interactive` (Q&A simulation), `publickey` (recorded, always rejected), `NoClientAuth` probe login
- Full shell syntax parsing (`mvdan.cc/sh` AST): `$()` command substitution, `&& / || / ;` composition, pipes, glob expansion, redirection, background jobs
- Virtual network emulation (`internal/vnet`): `ping / curl / wget / nc` send no real packets; target IP / port / URL are recorded
- SFTP subsystem emulation: list / download / upload all go through the virtual FS; uploaded content captured as `file.written` events
- Rule engine + risk scoring (`internal/detect`): 6 rule families — brute force, recon, payload delivery, reverse shell, persistence, lateral movement — per-connection cumulative score + severity alerts
- Alerting: `alert` events persisted + optional Webhook (Feishu / DingTalk / Slack bot)

**Planned (M3)**

- YARA payload detection, SIEM/CEF export, attack-chain visualization

---

## Quick Start

```bash
# Build (Windows)
go build -o honeypot.exe ./cmd/honeypot

# Run (reads configs/honeypot.yaml by default)
honeypot.exe

# Or directly
go run ./cmd/honeypot -config configs/honeypot.yaml
```

Test from another terminal:

```bash
# Try a weak password (default success_probability=0.02, may or may not be admitted)
ssh -p 2222 root@127.0.0.1
# password: 123456
```

You will land in the emulated shell. Run any command to observe the output, then:

```bash
go run ./cmd/dbquery        # inspect all captured attack events
```

### Sample session (smoke-test output)

```
$ ssh -p 2222 root@127.0.0.1
root@ubuntu-web-01:~# whoami
root
root@ubuntu-web-01:~# uname -a
Linux ubuntu-web-01 5.15.0-91-generic #101-Ubuntu SMP ... x86_64 GNU/Linux
root@ubuntu-web-01:~# cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
ubuntu:x:1000:1000:ubuntu:/home/ubuntu:/bin/bash
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
root@ubuntu-web-01:~# cat /etc/shadow
root:$6$rounds=656000$ZyHdQ8m4tZ8mK0n$...:19800:0:99999:7:::
root@ubuntu-web-01:~# exit
```

Captured events:

```
== auth_attempts ==
  conn_xxx | 2026-08-20T... | user=root pass=123456 method=password success=1 delay=512ms
== commands ==
  sess_xxx | 2026-08-20T... | cwd=/root | code=0 dur=12ms | whoami
  sess_xxx | 2026-08-20T... | cwd=/root | code=0 dur=15ms | uname -a
```

---

## Configuration

Edit `configs/honeypot.yaml`:

```yaml
server:
  listen: ["0.0.0.0:2222", "0.0.0.0:22222"]   # listen addresses
  max_connections: 500
  idle_timeout: 5m

ssh:
  server_version: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"   # spoofed version

auth:
  success_probability: 0.02   # admission probability when a weak password hits (0~1); prod 0.01~0.05, testing 1.0
  delay_ms: [200, 800]        # simulated auth delay (ms), mimics real password hashing
  keyboard_interactive: true  # keyboard-interactive auth toggle (default on)
  publickey: true             # public-key auth toggle (default on; recorded, always rejected)
  allow_no_auth: false        # allow probe login (high-value sessions, default off)
  weak_passwords: [root, admin, password, 123456, ...]   # weak password dictionary

vfs:
  hostname: "ubuntu-web-01"   # virtual hostname (prompt, /etc/hostname)
  users: ["root", "ubuntu", "www-data"]

storage:
  data_dir: "data"            # data directory (use an absolute path in production)
  driver: "sqlite,jsonl"      # sqlite structured + jsonl raw stream, can be combined

detect:
  enabled: true               # rule engine + risk scoring + alerts
  webhook_url: ""             # optional: alert JSON POST to webhook (e.g. Feishu/DingTalk)

log:
  level: "info"               # debug / info / warn / error
```

---

## Data & Event Inspection

Data layout:

```
data/
├── honeypot.db          # SQLite structured store (5 tables)
├── events/YYYY-MM-DD.jsonl     # JSONL raw event stream (daily rotation)
├── recordings/<sess_id>.ttyrec # ttyrec session recordings
└── host_key             # SSH host key (sensitive, never commit)
```

| Tool | Purpose                                                                                  | Usage |
|---|------------------------------------------------------------------------------------------|---|
| `cmd/dbquery` | Print all 5 tables (connections/attempts/sessions/commands/extended events)              | `go run ./cmd/dbquery` |
| `cmd/ttyshow` | Replay ttyrec recordings as timestamped text                                             | `go run ./cmd/ttyshow data/recordings/*.ttyrec` |
| `cmd/anti_attack` | SSH anti attack: listen & bounce traffic back to the client's source IP on the same port | `go run ./cmd/anti_attack -port 22 -log logs/anti_attack.log` |
| SQLite join | Correlate all behavior per attacker IP                                                   | `sqlite3 data/honeypot.db "SELECT c.source_ip, a.username, a.password FROM auth_attempts a JOIN connections c ON a.connection_id = c.id;"` |

> `auth_attempts` stores the **plaintext password** of every attempt; `commands` stores exit code / duration / output preview per command; the generic `events` table carries extended events (download / connect / file write / alert) with JSON payload.

---

## Build & Compile

The `scripts/` directory provides PowerShell build scripts that set `GOOS/GOARCH/CGO_ENABLED=0` (fully static build) automatically and verify the output binary's magic bytes, so you never ship a binary for the wrong platform.

### Native build (Windows)

```powershell
powershell -ExecutionPolicy Bypass -File scripts\build-win.ps1              # amd64 (default)
powershell -ExecutionPolicy Bypass -File scripts\build-win.ps1 -Arch arm64  # ARM64
```

Outputs go to `target/`:

| Artifact | Description          |
|---|----------------------|
| `target/honeypot-windows-amd64.exe` | honeypot main binary |
| `target/ttyshow-windows-amd64.exe` | ttyrec replay        |
| `target/dbquery-windows-amd64.exe` | event query          |
| `target/anti_attack-windows-amd64.exe` | SSH anti attack      |

The script verifies the first 2 bytes are `MZ` (PE magic).

### Cross-compile (Windows → Linux ELF)

```powershell
powershell -ExecutionPolicy Bypass -File scripts\build-linux.ps1            # amd64
powershell -ExecutionPolicy Bypass -File scripts\build-linux.ps1 -Arch arm64 # ARM64
```

Outputs go to `target/`: `honeypot-linux-amd64`, `ttyshow-linux-amd64`, `dbquery-linux-amd64`, `anti_attack-linux-amd64` (arm64 similarly). The script verifies the first 4 bytes are `7F 45 4C 46` (ELF magic) to prevent accidentally shipping a Windows PE.

> On a Linux build host you don't need the script — just `CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o honeypot ./cmd/honeypot`. The scripts are mainly for Windows devs cross-compiling to a Linux deploy target.

---

## anti_attack: SSH Anti Attack

`cmd/anti_attack` is a standalone companion to the honeypot: it listens on a local port, and on each accepted connection grabs the client's source IP, then dials back to that source IP on the same port and bidirectionally relays bytes. In a honeypot setup it's typically placed in front: an attacker scanning the port sees their traffic bounced back to themselves — no local real service exposed, while every incoming connection still gets logged (IP, byte counts, timing).

**Usage**

```powershell
anti_attack.exe -port 22 -log logs/anti_attack.log -log-level info
```

**Flags**

| Flag | Default | Meaning |
|---|---|---|
| `-port` | `22` | Local listen port. On accept, dial back to the client's source IP on this same port. |
| `-log` | `logs/anti_attack.log` | Active log file name; rotated by lumberjack to `<name>-YYYYMMDDTHHMMSS.NNN.log.gz` once `-log-size` is exceeded (NNN is the rotation index within the same second). |
| `-log-level` | `info` | `debug` / `info` / `warn` / `error` |
| `-log-size` | `100` | Max MB per log file before rotation. |
| `-log-backups` | `7` | Number of old log files to keep. |
| `-log-age` | `30` | Max days to retain old log files. |
| `-log-compress` | `true` | gzip rotated log files. |
| `-d` / `--daemon` | `false` | Run in the background: fork a child detached from the terminal. Linux only. |
| `-pidfile` | `logs/anti_attack.pid` | PID file path; the current PID is written here after daemon-mode startup. |

**Log layout**

Active log is written to the file specified by `-log`. When it exceeds `-log-size`, lumberjack archives it as `anti_attack-YYYYMMDDTHHMMSS.NNN.log.gz` (the `.000` / `.001` suffix is the rotation index within the same second). Archives older than `-log-age` days are auto-cleaned.

**Working with the honeypot & binding 22 as non-root**

`-port` defaults to 22 (privileged port — non-root can't bind it). The three authorization options (systemd `AmbientCapabilities` / `setcap` / iptables redirect) are described in the next section: "Deploying to Linux / Binding a low port as non-root".

If you'd rather avoid granting capabilities, point `-port` at a high port (e.g. `2222`) and have the honeypot listen on the same port. Attackers scanning `2222` hit `anti_attack` first and get bounced back, while the honeypot still serves high-interaction emulation independently.

**Running as a background daemon (Linux)**

```bash
./anti_attack-linux-amd64 -port 22 -log logs/anti_attack.log -d
```

The parent prints the child's PID and exits; the child lives on in a new session detached from the terminal (stdin/stdout/stderr go to `/dev/null`). The PID is written to `logs/anti_attack.pid` by default — override with `-pidfile <path>`. On Windows, use `nssm` or `sc.exe CreateService` to register it as a service.

---

## Deploying to Linux

### Transfer & systemd

```bash
scp target/honeypot-linux-amd64 root@<server>:/opt/honeypot/honeypot
scp configs/honeypot.yaml root@<server>:/opt/honeypot/configs/honeypot.yaml
```

```ini
# /etc/systemd/system/honeypot.service
[Unit]
Description=SSH Honeypot
After=network.target

[Service]
Type=simple
User=honeypot
WorkingDirectory=/opt/honeypot
ExecStart=/opt/honeypot/honeypot -config /opt/honeypot/configs/honeypot.yaml
Restart=always
PrivateTmp=true
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/opt/honeypot/data /opt/honeypot/logs

[Install]
WantedBy=multi-user.target
```

### Binding a low port as non-root (e.g. 22)

A non-root process cannot bind to privileged ports (< 1024) by default. Before binding the honeypot to 22, **move your real SSH off that port first**, otherwise you'll lock yourself out:

```bash
sed -i 's/^#\?Port .*/Port 2222/' /etc/ssh/sshd_config
systemctl restart sshd
# Confirm 2222 works before touching 22
```

**Option A: systemd ambient capability (recommended)**

Cleanest — no binary patching, no NAT, and `User=honeypot` stays non-root. Add two lines to the service unit:

```ini
[Service]
User=honeypot
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
```

After setting the listen port to 22, run `systemctl daemon-reload && systemctl restart honeypot`. The capability rides with the unit, so binary upgrades need no re-apply.

**Option B: setcap file capability**

Patch the binary directly (works because the project is statically compiled):

```bash
setcap 'cap_net_bind_service=+ep' /opt/honeypot/honeypot
systemctl restart honeypot
```

Caveat: re-run `setcap` every time you overwrite the binary (the capability is not carried by file content). If the service uses `NoNewPrivileges=true`, some kernels don't inherit file capabilities — prefer Option A.

**Option C: iptables redirect**

Keep the honeypot on a high port (e.g. `2222`) and redirect inbound 22 to it — zero capability granted, most secure:

```bash
iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
iptables-save > /etc/iptables/rules.v4   # Debian, persist
```

Deployment notes: open the honeypot port to the internet, **block outbound by default** (`iptables -A OUTPUT -m owner --uid-owner honeypot -j DROP`), isolate from production networks, run as non-root.

---

## Smoke Test

```powershell
# End-to-end: start honeypot → weak-password login → keyboard-interactive → shell syntax → VNet → SFTP → data persisted
powershell -ExecutionPolicy Bypass -File scripts\smoke.ps1
```

Test config `data/test.yaml` sets `success_probability: 1.0` so admission is guaranteed.

---

## Project Layout

```
honeypot-go/
├── cmd/
│   ├── honeypot/        # entry: wiring, graceful shutdown
│   ├── smoketest/       # smoke test client
│   ├── dbquery/         # SQLite ops query
│   ├── ttyshow/         # ttyrec replay
│   └── anti_attack/     # TCP reverse proxy: bounce traffic back to client's source IP on the same port
├── internal/
│   ├── config/          # YAML config load & validation
│   ├── event/           # event bus (publish/subscribe decoupling)
│   ├── ident/           # connection/session IDs
│   ├── ssh/             # x/crypto/ssh wrapper + SFTP subsystem emulation (sftp.go)
│   ├── auth/            # auth deception (password/keyboard-interactive/publickey)
│   ├── session/         # session lifecycle
│   ├── shell/           # AST parsing (parse.go) + command emulation (executor.go)
│   ├── vfs/             # in-memory virtual FS
│   ├── vnet/            # virtual network emulation (wget/curl/ping/nc)
│   ├── detect/          # rule engine + risk scoring + Webhook alerts
│   ├── tty/             # ttyrec recording
│   └── store/           # SQLite + JSONL persistence
├── configs/honeypot.yaml
├── scripts/             # build scripts (build-win.ps1 / build-linux.ps1) / smoke test
└── docs/architecture.md # full architecture design
```

See [docs/architecture.md](docs/architecture.md) for the full design (threat model, module details, data model, hardening, roadmap).

---

## Hardening Checklist

1. **Emulation isolation**: no real system commands are ever executed
2. **Outbound disabled**: VNet never sends real packets + firewall blacklist as a backstop
3. **Least privilege**: non-root, `ProtectSystem`, `NoNewPrivileges`
4. **Resource limits**: per-session timeout, max concurrent connections (anti resource-exhaustion)
5. **Anti-detection**: version fingerprint matches real OpenSSH
6. **Network isolation**: honeypot network physically/logically separated from production

---

## License

This project is released under the **GNU GPL-3.0** (strong copyleft). Any distribution, modification, or derivative work must also be released under GPL-3.0. The full text is in the `LICENSE` file at the repository root.

> If you modify and distribute this program, you must keep the copyright notice, mark the modification date, and provide the corresponding source. Network-facing deployments are subject to the corresponding AGPL-3.0 terms (contact the maintainer if you intend to switch to AGPL).
