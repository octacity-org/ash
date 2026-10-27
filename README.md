# ASH — Agentic Shell

ASH lets coding agents operate on other machines over SSH. It is a local Go binary with a CLI and MCP tools for execution, SFTP file access, and persistent shells. No remote ASH daemon is required.

## Install

On Linux AMD64/ARM64 or macOS Apple Silicon, install the latest stable GitHub release:

```sh
curl -fsSL https://raw.githubusercontent.com/octacity-org/ash/main/install.sh | sh
```

The installer verifies the archive against the release's SHA256SUMS.txt and installs
`ash` to `~/.local/bin` without sudo. Add that directory to your `PATH` if needed.
It requires `curl`, `tar`, and either `sha256sum` or `shasum`; Go is not required.
Run the same command again to update. To select a release or installation directory:

```sh
curl -fsSL https://raw.githubusercontent.com/octacity-org/ash/main/install.sh | ASH_VERSION=v0.3.1 ASH_INSTALL_DIR="$HOME/bin" sh
```

These URLs work after the installer is pushed to `main` and a matching release is
published. Windows users can extract `ash.exe` from the Windows archive on
[GitHub Releases](https://github.com/octacity-org/ash/releases).

Installation only places the executable on your machine. Configure a host and
register the MCP server with your client using the sections below.

## Build

Requires Go 1.26.5 or newer.

```sh
go build -o ash ./cmd/ash
./ash --help
```

## Configure a host

Create `~/.config/ash/config.toml`:

```toml
[hosts.example]
address = "server.example.com"
user = "remote-user"
# port = 22
# identity = "~/.ssh/id_ed25519"

[hosts.example.policy]
exec = true
read = true
write = true
```

Replace the address and user with your remote machine's values. Each capability defaults to `false`; `stat` requires `read`. Unknown configuration keys are rejected. Use `--config PATH` before the subcommand to select another configuration file.

Authenticate using keys from `SSH_AUTH_SOCK`, or an explicit identity file. Load encrypted keys into your SSH agent and omit `identity` in that case; an explicitly configured identity must be readable and unencrypted. ASH does not prompt for passwords or key passphrases.

ASH verifies the configured address and port against `~/.ssh/known_hosts`. Establish trust yourself with OpenSSH, verifying the host fingerprint through a trusted channel. For the example above:

```sh
ssh remote-user@server.example.com
```

Use `ssh -p PORT USER@ADDRESS` for a custom port. Listing hosts and starting MCP do not require a connection or a known-hosts file; remote operations require a trusted host key.

### Reuse an OpenSSH alias

An ASH host may reference an OpenSSH alias instead of duplicating connection details:

```toml
[hosts.example]
ssh_alias = "my-server"

[hosts.example.policy]
exec = true
read = true
write = true
```

ASH resolves the alias once at startup by running the installed OpenSSH client (`ssh -G -- ALIAS`), so aliases, `Include`, and `Match` behave exactly as OpenSSH does. Precedence is explicit ASH value, then the resolved OpenSSH value, then the ASH default; the ASH host name stays separate from the resolved address. Resolved fields include hostname, user, port, identity files (loaded in order), `IdentityAgent`, `HostKeyAlias`, and `UserKnownHostsFile` (every listed file that exists is trusted; at least one must exist). ASH deliberately rejects an alias that uses `ProxyJump`, `ProxyCommand`, `CertificateFile`, `PKCS11Provider`, or `UserKnownHostsFile none`, naming the directive before any network access, rather than emulating it partially. Hosts without `ssh_alias` keep the pure-Go behavior and never invoke OpenSSH.

### Restrict a host

Capabilities can be narrowed without breaking existing configuration:

```toml
[hosts.example.policy]
exec = true
read = true
write = true
read_roots = ["/var/log", "/srv/app"]
write_roots = ["/srv/app"]
cwd_roots = ["/srv/app"]
allowed_commands = ["systemctl", "cat"]
# allow_shell = true          # required to keep shell-code exec once allowed_commands is set
max_timeout_seconds = 30
max_input_bytes = 65536
max_output_bytes = 1048576
max_stream_bytes = 10737418240 # cap for one streamed exec or CLI read/write; 0 or unset = unlimited
# forward = true
# forward_targets = ["localhost:5432"] # exact HOST:PORT targets `ash forward` may reach; empty = any
```

Roots are **remote absolute POSIX paths**. Empty fields preserve the previous broad behavior. Paths are canonicalized through SFTP (`realpath` of the target, or of the nearest existing parent for a create) and enforced component-wise before the operation, so symlink escapes are rejected. `allowed_commands` restricts argv execution only; shell code can invoke anything, so when it is set ASH refuses shell-code `exec` and persistent shells unless `allow_shell = true`, which explicitly bypasses executable restrictions. Persistent shells also honor `cwd_roots` for their starting directory, `max_input_bytes` for each send, and `max_timeout_seconds` as a cap on `wait`. Timeout, input, and output bounds allow a request to choose *smaller* values but never larger ones, and configurable bounds may not exceed the compiled hard caps. `max_input_bytes` and `max_output_bytes` apply to buffered exec only; streamed exec (`--stream`, `rsh`) and whole-file CLI `read`/`write` are bounded by `max_stream_bytes` instead. `forward` is a separate capability, off by default, and `forward_targets` limits it to exact `HOST:PORT` strings as seen from the remote host.

Set a top-level `audit_log` to append structured, local JSONL records of operations:

```toml
audit_log = "~/.local/state/ash/audit.jsonl"
```

Each record contains the time, operation, ASH host, policy decision, duration, result category, byte counts, and truncation. `bytes_in` counts payload sent to the host (stdin, written content, shell input) and `bytes_out` payload returned from it (command output, read content, shell output); `truncated` marks a bounded result. Records deliberately omit command text, argv values, paths, file contents, environment variables, credentials, stdout, and stderr. The file is created owner-only (`0600`). Audit writes are fail-open: a write error never fails the operation.

## CLI

```sh
./ash hosts
./ash host add example --address server.example.com --user remote-user --exec --read --write
./ash host add box --ssh-alias my-server --shell-backend tmux --read
./ash doctor
./ash doctor example
./ash doctor example --json
./ash exec example -- uname -a
./ash exec example --cwd '~/projects/app' --env CI=true --timeout 30s -- go test ./...
./ash execv example -- systemctl is-active nginx
printf '{"ok":true}' | ./ash exec example --stdin -- elephant receive
tar cf - -C ./site . | ./ash exec example --stream -- tar xf - -C /srv/site
rsync -a -e './ash rsh' ./site/ example:/srv/site/
./ash forward example 5432:localhost:5432
./ash read example /etc/os-release
./ash read example /var/log/syslog --offset -65536
printf 'hello from ASH\n' | ./ash write example /tmp/ash-test.txt
printf 'hello from ASH\n' | ./ash write example /tmp/ash-test.txt --atomic
./ash stat example /tmp/ash-test.txt
./ash list example /tmp
./ash mkdir example /tmp/ash-dir
./ash rename example /tmp/ash-dir /tmp/ash-dir2
./ash remove example /tmp/ash-dir2
./ash download example /tmp/remote-tree ./local-tree
./ash upload example ./local-tree /tmp/remote-tree
```

`exec` joins everything after `--` with spaces into **shell code**, executed through the remote user's shell. For shell expressions or arguments containing spaces, pass one quoted command string:

```sh
./ash exec example -- 'printf "%s\n" "hello world"; exit 7'
```

`cwd` and environment values are escaped as literal values; environment names must be valid shell identifiers. Execution assumes a POSIX-compatible remote shell. Quote remote `~/` paths so your local shell does not expand them. SFTP resolves `~/` against its initial remote directory, normally the user's home.

`execv` runs a structured `PROGRAM ARG...` without a shell, quoting every word literally, so `allowed_commands` can be enforced. It shares `--cwd`, `--env`, and `--timeout` with `exec`.

Command stdout and stderr stay separate, and the CLI returns the remote process exit code. ASH failures print a diagnostic to stderr and return `1`. `hosts`, `stat`, and `list` print JSON; `read` writes file bytes to stdout, and with `--offset N` and/or `--limit N` writes a slice of a file of any size (a negative offset counts from the end; the limit is at most 4 MiB); `write` consumes stdin and creates or truncates the file. Parent directories must exist. Whole-file `read` and `write` stream between the terminal and SFTP, so the CLI has no file size limit; the transfer fails after 30 seconds without progress, and `max_stream_bytes` caps it. A `write` that fails part-way can leave a partial file. Pass `--atomic` to `write` to replace the destination through a same-directory temporary file, fsync, and rename, so an interrupted write leaves the prior file intact. An atomic replacement keeps the existing file's permission bits (new files get `0644`); ownership is not preserved.

`mkdir` creates one directory without implicit parents. `rename` moves a file or directory. `remove` deletes a file or an empty directory and is never recursive; enumerate a tree with `list` before deleting it. `download` and `upload` map a bounded remote tree to and from a local directory without archives: remote symlinks are skipped, and absolute paths, `..`, NUL, duplicates, type conflicts, depth/entry/byte limits (depth 32, 1000 entries, 4 MiB) are rejected before the first remote mutation. A recursive transfer that fails part-way leaves earlier entries in place; there is no rollback. The CLI keeps each file's permission bits (for example an executable `0755` script or a `0600` key) in both directions; setuid, setgid and sticky bits are not transferred, directories are created with the default mode, and uploads from Windows and through `ash_upload` write files as `0644`.

`host add` appends a minimal, deny-by-default entry to the configuration file. It never overwrites an existing host or an unparseable file; capabilities are granted explicitly with `--exec`, `--read`, and `--write`. Pass `--ssh-alias ALIAS` instead of `--address`/`--user` to reference an OpenSSH alias, and `--shell-backend tmux` to select the tmux backend.

`doctor` validates configuration and SSH trust without connecting when no host is named. For a host it reports configuration, host resolution, policy, known-hosts, host-key trust, authentication, POSIX shell availability, remote cache permissions, and availability of the host's shell backend (Zellij or tmux) as separate checks, each with an actionable hint, and exits non-zero when a check fails. It never prints identity paths, key material, or environment secrets. Pass `--json` for stable structured output.

Pass `--stdin` to forward standard input to the remote command, avoiding shell-quoting and command-size limits. Input is bounded at 64 KiB and fails clearly when exceeded. Without `--stdin`, ASH neither reads nor forwards standard input.

Pass `--stream` to `exec` or `execv` to connect standard input, output and error directly to the remote command, like `ssh host command`. Nothing is buffered, so the 64 KiB input and 8 MiB output caps do not apply; this is the way to pipe archives, dumps or logs through ASH. With `--stream`, `--timeout` limits how long no data may move in either direction (default five minutes, capped by `max_timeout_seconds`), so a long transfer that keeps moving data is not cut off. `max_stream_bytes` caps the total bytes one streamed command may move. Policy checks are the same as for buffered exec, and the audit log records the bytes that actually moved. No pseudo-terminal is allocated; use persistent shells for interactive programs.

`rsh [-l USER] HOST COMMAND...` is the same streamed exec with the calling convention of `rsh`, so rsync can use ASH as its remote shell: `rsync -a -e 'ash rsh' SRC host:DEST`. The command words are joined with spaces and run by the remote shell, as with `ssh`, which means `allowed_commands` refuses it unless `allow_shell = true`. `-l` must match the host's configured user, because ASH only connects as that user. OpenSSH options such as `-o` are not accepted, so `rsh` does not replace `GIT_SSH_COMMAND`.

`forward HOST LOCAL_PORT:TARGET_HOST:TARGET_PORT` forwards a local port through the host, like `ssh -L`, until you press Ctrl-C. It listens on `127.0.0.1` only; `LOCAL_PORT` `0` picks a free port, which ASH prints. The target is resolved and dialed by the remote SSH server, so `localhost` means the remote machine. The host needs the `forward` capability, the target must appear in `forward_targets` when that list is set, and the server must allow TCP forwarding (`AllowTcpForwarding`, on by default in OpenSSH). All connections share one SSH connection; if it drops, connections fail until you restart the command. Each forwarded connection is audited with its target and byte counts.

Commands default to a five-minute timeout. File operations default to 30 seconds. Cancellation closes the SSH connection/session; it does not guarantee termination of detached remote descendants. Verified SSH connections are pooled, and a pooled connection keeps one SFTP session open for consecutive file operations.

Each buffered command output stream is capped at 8 MiB and reports truncation. MCP reads and writes, ranged reads, and tree transfers are capped at 4 MiB. These limits bound captured output/file data, not all memory used by an MCP client's incoming protocol message.

## Persistent shells

Persistent shells use a per-host backend. Zellij ([headless CLI](https://zellij.dev/documentation/cli-recipes.html), 0.44 or newer) is the default; tmux is selected with `shell_backend = "tmux"` and requires tmux on the remote host.

```toml
[hosts.example]
address = "server.example.com"
user = "remote-user"
shell_backend = "tmux"
```

CLI and MCP behavior is backend-independent; backend-specific features are never exposed. Both backends map ASH-generated IDs to a reserved remote namespace (`ash-<id>`) and query the backend for liveness rather than trusting local metadata, so ASH lists and controls only its own sessions. tmux uses a dedicated server socket (`tmux -L ash`), keeping ASH sessions fully separate from the user's personal sessions. Shells are separate from one-shot `exec`: shell variables, working directory, and running commands survive ASH process exits and SSH disconnects. ASH opens short SSH connections to control the backend; it does not keep an SSH session alive.

```sh
./ash shell create example --cwd '~/projects'
./ash shell list example
```

Creation returns JSON containing an ASH `id`, `host`, and `backend`. Set `SHELL_ID` to the returned `id`, then:

```sh
printf 'pwd\n' | ./ash shell send example "$SHELL_ID"
./ash shell read example "$SHELL_ID"
./ash shell wait example "$SHELL_ID" --until READY --timeout 30s
./ash shell close example "$SHELL_ID"
```

`send` accepts an optional literal INPUT argument, or reads stdin when omitted. It adds no newline: include one to submit a command. It returns after delivering input, without waiting for the shell command to finish. Input is UTF-8 without NUL and is limited to 64 KiB. Over MCP, `ash_shell_send` returns a `cursor` captured just before delivery; pass it to `ash_shell_wait` to observe only the output that input produced, without a separate read.

`read` returns rendered terminal text and available scrollback, with stdout and stderr merged. Without a cursor it returns a full snapshot (and may repeat previous output). `--json` includes an opaque `cursor`; pass `--cursor VALUE` on the next read to receive only output added since the snapshot that produced it. A cursor is a byte-delta optimization over append-like output, not a terminal event log: if the pane changed, scrollback was truncated, or a redraw altered earlier bytes, the read returns a full snapshot with `resync: true` and a fresh cursor. Expired or malformed cursors resynchronize rather than fail. Snapshots are bounded by the existing 8 MiB transport limit and report truncation. This is a polling interface, with no streaming or full-screen TUI support and no per-command exit status. Use one-shot `exec` when you need a structured command result.

`wait` blocks until new output arrives, or until a `--until` literal or `--regex` expression appears, and returns the observed output plus the next cursor. `--timeout` must be positive and is capped at five minutes. On timeout the persistent shell stays open; `--json` reports `matched`, `timed_out`, `truncated`, and `resync`. Matching runs against the bounded new output across chunk boundaries. This observes terminal output, not command completion or exit status.

Every shell operation requires the host's existing `exec` capability and the same shell-code permission as `exec` (see `allowed_commands` above). No additional policy flag is introduced. ASH-generated IDs map to reserved remote session names; ASH lists and controls only sessions in that namespace. Liveness is queried from Zellij, with no local session metadata to become stale. Exited sessions are not listed. Closing a shell is idempotent and also removes its ASH-owned backend configuration after an external termination. The namespace is organizational ownership, not isolation from other processes running as the same remote account. Zellij startup settings live in the remote `~/.cache/ash/shells/ID/config.kdl` until the shell is closed; this file is configuration, not a liveness record.

Control operations have a 30-second deadline. That deadline limits the control request, not the lifetime of the persistent shell or a command sent to it. Persistence covers ASH/SSH disconnects, not host reboots or termination of Zellij. Treat a canceled or failed send as potentially delivered; do not blindly retry commands with side effects.

## Set up MCP with a coding agent

`ash setup` registers ASH as a stdio MCP server using the absolute ASH executable path and your configuration file. Run it with the same `--config` value (if any) that you use for other commands:

```sh
./ash setup codex
./ash setup opencode --scope project
./ash setup freebuff --scope project
./ash setup codex --print
```

| Agent | Scope | File |
| --- | --- | --- |
| Codex | user | `$CODEX_HOME/config.toml` (default `~/.codex/config.toml`) |
| Codex | project | `.codex/config.toml` |
| OpenCode | user | `~/.config/opencode/opencode.json` |
| OpenCode | project | `opencode.json` |
| freebuff | project | `.agents/mcp.json` |

Re-running setup updates the existing ASH entry in place instead of creating a duplicate, and leaves unrelated settings and comments untouched. `--print` shows the proposed configuration without writing any file. Restart the agent after setup so it reloads its configuration and starts the ASH server. Unsupported agents receive a clear diagnostic and a manual stdio configuration example.

## MCP

Configure your MCP client to launch the built binary over stdio:

```json
{
  "mcpServers": {
    "ash": {
      "command": "/absolute/path/to/ash",
      "args": ["--config", "/absolute/path/to/config.toml", "mcp"]
    }
  }
}
```

Client configuration formats vary. ASH serves only stdio; stdout is reserved for protocol messages.

| Tool | Inputs | Result |
| --- | --- | --- |
| `ash_hosts` | `{}` | Public host metadata, capabilities, `shell_backend`, and any policy limits (`read_roots`, `write_roots`, `cwd_roots`, `allowed_commands`, `allow_shell`, `max_timeout_seconds`, `max_input_bytes`, `max_output_bytes`, `max_stream_bytes`, `forward_targets`) |
| `ash_exec` | `host`, `command` **or** `argv`; optional `cwd`, `env`, `timeout_ms`, `stdin`, `stdin_base64` | `exit_code`, `stdout`, `stderr`, truncation flags, `duration_ms` |
| `ash_read` | `host`, `path`; optional `encoding` (`text`/`base64`), `offset`, `limit` | `content` or `content_base64`, and byte `size`; slice reads add `offset` and `file_size` |
| `ash_write` | `host`, `path`, `content` or `content_base64` | Written byte `size` |
| `ash_stat` | `host`, `path` | `path`, `size`, `mode`, `is_dir`, `modified_at` |
| `ash_list` | `host`, `path` | `entries`: direct children with `name`, `path`, `size`, `mode`, `modified_at`, `is_dir`, `symlink` |
| `ash_mkdir` | `host`, `path` | `ok` |
| `ash_rename` | `host`, `from`, `to` | `ok` |
| `ash_remove` | `host`, `path` | `ok` (non-recursive) |
| `ash_write_atomic` | `host`, `path`, `content` or `content_base64` | Written byte `size` |
| `ash_download` | `host`, `path` | `entries`: bounded tree with `path`, `is_dir`, `mode`, `size`, `content_base64` |
| `ash_upload` | `host`, `path`, `entries` | Written byte `size` |
| `ash_shell_create` | `host`; optional `cwd` | `id`, `host`, `backend` |
| `ash_shell_list` | `host` | `shells`: live ASH-owned shells |
| `ash_shell_send` | `host`, `shell_id`, `input` | `sent`, `cursor` (captured before delivery) |
| `ash_shell_read` | `host`, `shell_id`; optional `cursor` | `content`, `cursor`, `truncated`, `resync` |
| `ash_shell_wait` | `host`, `shell_id`, `timeout_ms`; optional `cursor`, `until`, `regex` | `content`, `cursor`, `matched`, `truncated`, `resync`, `timed_out` |
| `ash_shell_close` | `host`, `shell_id` | `closed` |

`ash_exec` accepts standard input as UTF-8 `stdin` or base64 `stdin_base64` (mutually exclusive, at most 64 KiB); set either to an empty value to send empty input. A non-zero remote process exit is a successful MCP tool result. Connection, authentication, trust, policy and timeout failures are tool errors. `ash_read` returns UTF-8 `content` by default and rejects invalid UTF-8; pass `encoding: "base64"` for binary files. Setting `offset` or `limit` reads a slice of a file of any size (negative `offset` tails it); text slices drop a partial UTF-8 character at either edge and report the adjusted `offset`, so the next slice can start at `offset + size`. `ash_write` and `ash_write_atomic` accept `content` or `content_base64`, but not both. Host listings omit identity paths and authentication internals.

Capabilities grant access with the remote account's permissions. A bare boolean `exec`/`read`/`write`/`forward` does not constrain paths, commands or targets, and an enabled `exec` capability can itself read or modify files. Optional policy fields (`read_roots`, `write_roots`, `cwd_roots`, `allowed_commands`, `allow_shell`, `forward_targets`, bound settings) add enforcement; configure only hosts and accounts you intend the connected agent to operate.

## Architecture

CLI and MCP call the same service layer. Services resolve hosts, enforce policy, and set deadlines. The transport interface implements execution and file operations; its SSH backend pools verified SSH connections and uses SFTP. Transport code does not make authorization decisions. A separate shell service enforces the same host policy and calls a shell backend interface. The Zellij backend uses the SSH transport for short control commands; CLI and MCP contain no Zellij-specific logic.

ASH excludes full-screen terminal attachment, jobs, synchronization, forwarding, discovery, sudo handling, and HTTP.

## Verify

```sh
go test ./...
go vet ./...
```

The tests cover configuration, policy, shell escaping, output limits, CLI behavior and the official MCP client/server protocol. Run `ASH_INTEGRATION=1 go test -race ./integration` to exercise a real local OpenSSH daemon. See [integration](integration/README.md) for prerequisites. The daemon fixture is skipped unless explicitly enabled.

Persistent-shell integration requires a trusted host with Zellij 0.44 or newer (the tmux backend is unit-tested against exact command construction; opt-in remote tmux tests can use the same environment):

```sh
ASH_ZELLIJ_HOST=example ASH_ZELLIJ_CONFIG="$HOME/.config/ash/config.toml" \
  go test -v ./integration ./cmd/ash -run 'TestZellij|TestPersistentShellMCPReconnect'
```

These opt-in tests create and clean up their own remote ASH sessions. They cover shell creation, state and output across reconnects, listing, external termination, and cleanup. Ordinary test runs skip them. The host must already be configured and trusted.

## CI and releases

[GitHub Actions](.github/workflows/ci.yml) follows Elephant's native build and release workflow. Pushes, pull requests, and manual runs check formatting, release packaging tests, Go tests (including real MCP subprocesses), race detection, and `go vet` on:

- Linux ARM64 (`ubuntu-24.04-arm`)
- Linux AMD64 (`ubuntu-24.04`)
- Windows AMD64 (`windows-2022`)
- macOS ARM64 (`macos-15`)

The two tests that execute a POSIX shell locally run on Unix runners. Configured-host Zellij tests and the opt-in local OpenSSH daemon fixture retain their explicit opt-in settings; the standard CI run needs no SSH credentials.

Pushing a tag such as `v0.3.1` or `v0.3.1-rc.1` builds four native release archives. Unix targets use `.tar.gz`; Windows uses `.zip`. Each contains the executable, this README, and dependency/Go license notices. A release-wide `SHA256SUMS.txt` covers exactly those four archives.

The release job waits for every platform to succeed, creates or resumes a draft GitHub release, uploads all assets, then publishes it. Tags with a prerelease suffix are marked as prereleases. Already-published releases are not overwritten. Release publishing uses the workflow's GitHub token with `contents: write`; build jobs have read-only permissions.

Release builds stamp the same version into `ash --version` and MCP server metadata. Branch builds use `dev-COMMIT`; ordinary local builds report `dev`.

```sh
python3 -m unittest discover -s scripts -p 'test_*.py' -v
python3 scripts/release.py version v0.3.1-rc.1
```

The workflow becomes active once this project is pushed to GitHub. Tagging and publishing are separate from implementing these workflow files.
