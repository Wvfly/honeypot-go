# honeypot-go

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

### Sample session

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

| Tool | Purpose | Usage |
|---|---|---|
| `cmd/dbquery` | Print all 5 tables (connections/attempts/sessions/commands/extended events) | `go run ./cmd/dbquery` |
| `cmd/ttyshow` | Replay ttyrec recordings as timestamped text | `go run ./cmd/ttyshow data/recordings/*.ttyrec` |
| SQLite join | Correlate all behavior per attacker IP | `sqlite3 data/honeypot.db "SELECT c.source_ip, a.username, a.password FROM auth_attempts a JOIN connections c ON a.connection_id = c.id;"` |

> `auth_attempts` stores the **plaintext password** of every attempt; `commands` stores exit code / duration / output preview per command; the generic `events` table carries extended events (download / connect / file write / alert) with JSON payload.

---

## Deploying to Linux

### Cross-compile (produce Linux ELF from Windows)

```powershell
powershell -ExecutionPolicy Bypass -File scripts\build-linux.ps1            # amd64
powershell -ExecutionPolicy Bypass -File scripts\build-linux.ps1 -Arch arm64 # ARM
```

The script sets `GOOS/GOARCH/CGO_ENABLED=0` (fully static build) and **verifies the ELF magic bytes** to prevent accidentally shipping a Windows PE binary.

### Transfer & systemd

```bash
scp honeypot-linux-amd64 root@<server>:/opt/honeypot/honeypot
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
│   └── ttyshow/         # ttyrec replay
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
├── scripts/             # smoke test / cross-compile scripts
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
