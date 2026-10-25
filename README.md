# Unix File Integrity Monitor (fim)

A File Integrity Monitor written in pure C for Linux/Unix. It watches a directory tree, hashes every file with SHA-256, and raises a real-time alert the moment any file is **modified**, **created**, or **deleted** - a mini intrusion-detection tool built only on Unix system calls.

Unix System Programming Mini Project.

## Features

- SHA-256 hashing implemented from scratch in C (no external crypto library)
- Three modes: `init` (create baseline), `check` (one-shot scan), `monitor` (continuous watch)
- Real-time alerts: `MODIFIED`, `NEW FILE`, `DELETED` with timestamps
- Daemon mode: runs in the background and logs alerts to a file
- Graceful Ctrl+C shutdown with a summary report
- Recursive directory traversal, colored terminal output
- `check` mode returns an exit status, so it drops straight into shell scripts

## Unix System Programming concepts used

| Concept | System calls | Where it is used |
|---|---|---|
| File I/O | `open()`, `read()`, `close()` | Reading file contents for SHA-256 hashing |
| Directory handling | `opendir()`, `readdir()`, `closedir()` | Recursive traversal of the watched directory tree |
| File metadata | `lstat()` | File type, size and modification time |
| Process creation | `fork()`, `setsid()` | Daemon mode - detaches and runs in the background |
| Signal handling | `sigaction()` on `SIGINT` / `SIGTERM` | Graceful shutdown with a summary on Ctrl+C |
| Exit statuses | `exit()` return codes | `check` returns 0 (clean), 1 (changes), 2 (error) |

## Requirements

- Linux or any Unix-like OS
- `gcc` and `make`

No external libraries needed - everything is standard C and POSIX.

## Build

```bash
git clone https://github.com/hadhiabdulla/unix-file-integrity-monitor.git
cd unix-file-integrity-monitor
make
```

(or directly: `gcc -Wall -Wextra -O2 -std=c11 -o fim fim.c`)

## Usage

```bash
# 1. Create the integrity baseline for a directory
./fim init ~/secure_docs

# 2. Watch it live (default scan every 2 seconds)
./fim monitor ~/secure_docs

# Custom interval (every 5 seconds)
./fim monitor ~/secure_docs -i 5

# Background daemon - alerts are appended to <dir>/.fim.log
./fim monitor ~/secure_docs --daemon

# One-shot integrity check (exit code 1 if anything changed)
./fim check ~/secure_docs
```

Stop the monitor with `Ctrl+C` - it prints a summary of how long it watched and how many alerts it raised.

## Demo

### Build and create a baseline
![Build and init](https://github.com/hadhiabdulla/unix-file-integrity-monitor/releases/download/v1.0/01_build_and_init.png)

### Live alerts when files are tampered with
![Live alerts](https://github.com/hadhiabdulla/unix-file-integrity-monitor/releases/download/v1.0/02_live_alerts.png)

### Daemon mode and scripted integrity check
![Daemon and check](https://github.com/hadhiabdulla/unix-file-integrity-monitor/releases/download/v1.0/03_daemon_and_check.png)

## How it works

1. `init` walks the directory tree with `opendir()`/`readdir()`, hashes every regular file with SHA-256, and stores the hashes in a hidden baseline file (`<dir>/.fim_baseline`).
2. `monitor` re-scans the tree on a fixed interval and diffs the fresh scan against the baseline:
   - path present but hash changed -> **MODIFIED**
   - path not in the baseline -> **NEW FILE**
   - baseline path missing from the scan -> **DELETED**
3. Every alert updates the in-memory baseline, so each change is reported exactly once.
4. In `--daemon` mode the process calls `fork()` + `setsid()`, detaches from the terminal, and appends alerts to `<dir>/.fim.log`.

## Project structure

```
unix-file-integrity-monitor/
├── fim.c       # complete source (monitor + SHA-256, single file)
├── Makefile    # build with `make`
└── README.md
```

(Demo screenshots above are attached to the [v1.0 release](https://github.com/hadhiabdulla/unix-file-integrity-monitor/releases/tag/v1.0).)
