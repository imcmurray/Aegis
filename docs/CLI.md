# Native `aegis` CLI

Production **file-backed** vault backend. Same `VaultRequest` / `VaultResponse` protocol as WASM, the Freenet delegate, and `aegis-dev-vault-server`. No HTTP. No TCP.

Protocol version: **`1`**. `aegis --protocol-version` prints that integer. Bump only when the JSON/CBOR schema breaks.

Install the **attested** linux-x86_64 CLI from the matching GitHub Release
(built `--locked` on GitHub Actions with rustc 1.98.1, SHA-256 published,
provenance attested). omarchy-aegis refuses any other binary.

```bash
tag=v2.0.0-rc.1.1
base=https://github.com/imcmurray/Aegis/releases/download/$tag
curl -fsSL -o /tmp/SHA256SUMS "$base/SHA256SUMS"
curl -fsSL -o /tmp/aegis-x86_64-unknown-linux-gnu "$base/aegis-x86_64-unknown-linux-gnu"
(cd /tmp && sha256sum -c SHA256SUMS --ignore-missing)
install -D -m 0755 /tmp/aegis-x86_64-unknown-linux-gnu ~/.local/bin/aegis
rm -f /tmp/aegis-x86_64-unknown-linux-gnu /tmp/SHA256SUMS
aegis --protocol-version
```

Developer-only source build (not what the plugin verifies):

```bash
cargo install --locked --path tools/cli
# or
cargo run -p aegis-cli --locked -- status
```

## Process model

Argon2id is ≥ 64 MiB. Unlocking on every `aegis search` is not acceptable.

| Process | Role |
|---|---|
| `aegis agent [--foreground]` | Long-lived session. Holds `FileStore` + optional `ActiveSession`. Auto-locks after idle (default 300s). Listens on a user-only unix socket. |
| Foreground commands | If the agent is running, send the request to it. Otherwise `status` / `create` / `import` / locked `export` are one-shot. `search` / `copy` / `get` on a locked vault return `ErrorCode::Locked` — they do not prompt+unlock+exit. |

`aegis unlock` starts the agent if needed, then unlocks it.

The agent locks and drops the in-memory session on SIGTERM/SIGINT.

## Paths

Never `~/.local/share/aegis-dev`.

| | Default | Override |
|---|---|---|
| Data | `$AEGIS_DATA` or `$XDG_DATA_HOME/aegis` or `~/.local/share/aegis` | `--data-dir` |
| Runtime | `$AEGIS_RUNTIME` or `$XDG_RUNTIME_DIR/aegis` or `/run/user/$UID/aegis` | `--runtime-dir` |

```
<data>/secrets/              FileStore
<data>/sync/vault_sync.cbor  FileSyncTransport (local MVR)
<runtime>/agent.sock         AF_UNIX, mode 0600 (dir 0700)
<runtime>/agent.pid
```

## Passphrases

Never on argv, in the environment, or in the process title.

- Interactive tty: echo-off prompt (`rpassword`)
- Non-interactive: `--passphrase-file -` (stdin) or `--passphrase-file <path>` (file must be mode `0600`)
- No `--passphrase` flag

Import honors D18: backup passphrase ≠ new live-vault passphrase (`--backup-passphrase-file` and `--new-passphrase-file`).

## JSON / CBOR contract

`--json` and `aegis rpc` use the same serde tags as `common/src/messages.rs`:

- Request: tagged field **`op`**, snake_case (`{"op":"status"}`)
- Response: tagged field **`type`**, snake_case (`{"type":"status",...}`)
- Byte fields (`blob`, `kit`, …) are JSON arrays of integers (`serde_bytes`)

```
aegis rpc                 # one JSON object per stdin line → one JSON line out
aegis rpc --cbor          # raw CBOR request on stdin, CBOR response on stdout
```

Agent socket: length-prefixed CBOR (`u32` little-endian length, then `VaultRequest` / `VaultResponse` bytes). Max frame 16 MiB.

`ListSummaries` / `aegis search` return `EntrySummary` only (no passwords, notes, TOTP secrets, or history).

## Commands

```
aegis status | create | unlock | lock
aegis agent [--foreground] [--lock-after <secs>]
aegis agent status | stop
aegis search [query]
aegis folders
aegis generate
aegis copy <id-or-query> [--field password|username|totp|url] [--stdout] [--no-clear]
aegis totp <id-or-query>
aegis get <id> [--json | --reveal]
aegis export <path.aegis>
aegis import <path.aegis>
aegis import --preview <path.aegis>
aegis import --replace <path.aegis>
aegis rpc [--cbor]
```

Add entries with `aegis rpc` `upsert_entry` (no TUI editor in v1).

### Import / `--replace`

- Default `aegis import` **refuses** if a vault already exists (`already_exists`).
- `--replace` wipes the existing vault and restores **backup data** as a **new** live identity (new `vault_id` / RootSecret). Same D18 rule: `--new-passphrase-file` must differ from the backup password.
- This is **not** Recovery Kit identity-preserving restore (`import_recovery_kit`).
- `--preview` is dry-run only and **conflicts** with `--replace`.

## Copy / wipe

`aegis copy` asks the **agent** for `GetEntry` / `GenerateTotp`, then writes the secret:

1. `AEGIS_CLIPBOARD_FILE` if set (tests)
2. `AEGIS_CLIPBOARD_CMD` (secret on stdin, never in argv)
3. `wl-copy` if present
4. `xclip -selection clipboard`
5. `--stdout` only when requested

Clipboard is wiped after **30 seconds** (`CLIPBOARD_CLEAR_SECONDS`) unless `--no-clear`. The wipe is a detached `aegis __wipe-clipboard` child — the secret is not placed on `sh -c` argv.

## KDF

Default `create` is production Argon2id (64 MiB, t=3). Tests/smoke:

```
AEGIS_KDF=test cargo run -p aegis-cli -- --data-dir /tmp/aegis-smoke create
```

`AEGIS_KDF=test` is for the native CLI / unit tests only. Browser WASM create still ignores it and uses `generate_v2()`.

## Logging

Ops are logged by name only (`create_vault`, `unlock`, `list_summaries`, …). Passphrases, entry secrets, and recovery keys are not logged.
