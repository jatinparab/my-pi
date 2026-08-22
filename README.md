# my-pi mediated vault access

This package adds a cooperative, local Bitwarden boundary to Pi. It is designed for supported macOS TUI sessions and a locally installed `bw` CLI. The extension never puts a master password, `BW_SESSION`, item value, TOTP, note, key, or attachment bytes in model context.

## Setup and installation

1. Install Bitwarden CLI (`bw`) separately and sign in only through this extension's TUI wizard.
2. Ensure the macOS login Keychain is unlocked and the supported Pi runtime can load the native `@napi-rs/keyring` dependency.
3. Install this checkout with `./install.sh`, or install the package path with `pi install /absolute/path/to/my-pi`.
4. Restart Pi, or use `/reload` in a normal user session after installation. The extension does not call `/reload` itself.
5. Run `vault_items` with `{ "action": "status" }`. In TUI mode, an unconfigured vault opens the masked setup wizard. Choose US, EU, or a custom HTTPS origin, enter the account email, then enter the master password. The password is sent over strict local broker IPC and is cleared from the wizard object immediately after use.

The runtime is shared by Pi processes through a private Unix socket under `~/.pi/vault-broker` by default. The broker starts on demand, uses a dedicated `profile` directory with mode 0700, and exits after 30 minutes without requests. A Pi reload, session replacement, or shutdown only removes that Pi instance's status indicator; it does not stop a broker that other processes may be using.

## Tools and commands

### `vault_items`

The only model-facing metadata surface. Use:

```json
{ "action": "status" }
{ "action": "list", "limit": 20 }
{ "action": "search", "query": "github" }
{ "action": "inspect", "itemHandle": "h_..." }
```

List and search return bounded pages of Safe Metadata and an opaque cursor. Inspect returns descriptors and opaque material handles. Handles and cursors are lease-scoped: they expire after lock, forget, reconfiguration, profile replacement, session expiry, broker restart, or eviction. Native Bitwarden search may match hidden values; that membership oracle is accepted under the cooperative-agent model. Search text is never echoed by the extension.

### `vault_run`

Run one executable directly. Select material only by an opaque handle returned by `vault_items`:

```json
{
  "executable": "/usr/bin/ssh",
  "argv": ["host.example"],
  "materialEnv": { "SSH_KEY": "h_..." },
  "timeoutMs": 120000
}
```

Scalar material is delivered only through temporary environment mappings or one stdin handle. Attachment and bulk/binary stdin are streamed without writing decrypted files. Text stdout/stderr is bounded and sanitized; selected material and common JSON, URL, base64, base64url, and hexadecimal encodings are removed. Bulk/binary runs suppress stdout and stderr and return only execution metadata. Child processes use a minimal environment and direct, non-shell spawning.

### `vault_ssh_run`

Run one remote command via native, in-process SSH using Bitwarden-held SSH key material. No system `ssh`, shell, agent socket, decrypted key/config/known-host temporary file, or implicit interactive prompt:

```json
{
  "host": "example.com",
  "username": "deploy",
  "port": 22,
  "privateKeyHandle": "h_...",
  "passphraseHandle": "h_...",
  "command": "uptime",
  "stdinHandle": "h_...",
  "timeoutMs": 120000
}
```

Rules:
- Exactly one of non-secret `host` string or opaque `hostHandle` (for host material) is required.
- `username` defaults to `root`, `port` defaults to 22.
- `privateKeyHandle` must reference an `ssh-key` / `private-key` descriptor.
- Optional `passphraseHandle` and `stdinHandle` reference compatible material descriptors.
- Fixed SSH roles (host, key, passphrase, stdin) may reference different vault items, but all handles must have compatible descriptor types/delivery.
- Private key and passphrase remain memory-only for authentication; stdin is streamed to the remote command with backpressure.
- Remote command is executed without PTY, remote environment, working-directory, or interactive-shell surface.
- `ssh2` verifies the host key during handshake, before authentication. Unknown keys are accepted on first use; changed keys fail closed with the actionable non-secret error `host_key_changed`.
- Host-key trust state is atomically persisted before first-use acceptance in a mode-0600 file. Host/port identifiers and host-key verifiers are keyed digests; raw host text, raw host-key bytes, and their ordinary base64/hex encodings are never written. Malformed, insecure, full, or unwritable trust state fails closed as `host_key_unavailable`.
- Selected material and common encodings are redacted; bulk/binary stdin suppresses output under the same rules as `vault_run`.

### Lifecycle commands

These commands are intentionally TUI-only. Print, JSON, and RPC/non-TUI invocations fail closed; a model cannot approve or supply their secrets.

* `/vault-status` shows status and opens setup when needed.
* `/vault-lock` invalidates the Vault Session, item handles, material handles, cursors, and snapshots, then asks Bitwarden to lock. It retains the stored Keychain credential and dedicated CLI profile, so the next mediated request silently unlocks while Keychain access is available.
* `/vault-config` opens the same masked local wizard and securely replaces server/account configuration. The prior credential is never read into Pi model context, and the new credential appears only in the wizard-to-broker IPC path. The old session is invalidated before replacement. Replacement validates the new origin/account before mutation, probes and logs out an old profile even when no broker session exists, and deletes the dedicated stored credential before removing the old profile; it creates no backup or staging directory. Configure/login failures clear any partial credential and remove only the exact dedicated profile before returning a safe error.
* `/vault-forget` requires a real TUI confirmation. It invalidates all leases first, attempts Bitwarden logout where supported (otherwise lock where possible), deletes only the dedicated `pi.vault-broker` / `bitwarden-master-password` Keychain entry, removes only the dedicated broker `profile` directory, and reports a non-secret partial-cleanup warning if an OS/CLI cleanup step fails. It does not delete other Keychain entries or Bitwarden profiles.

Example flow: use `vault_items status`, list and inspect an item, run a child with a selected handle, `/vault-lock`, use `vault_items status` to silently unlock, `/vault-config`, and finally `/vault-forget` after confirming the warning.

## Data flow and boundary

```text
Pi tool/command -> strict length-prefixed Unix-socket IPC -> shared Vault Broker
                                                   |-> Keychain (credential)
                                                   |-> dedicated bw profile
                                                   |-> direct bw child (private session/material)
```

The broker owns Keychain access, CLI state, Vault Sessions, private decrypted snapshots, and credentialed child execution. A successful authentication or unlock creates an in-memory Vault Session for at most 15 minutes of inactivity. Locking and all replacement/forget paths clear the session and every opaque lease before doing further work. No session or material is stored in Pi session entries, process environment, argv, tool results, logs, temporary files, or output transcripts.

**Safe Metadata** is the allowlist: opaque handles, type, favorite, title, folder name, normalized HTTP(S) origins without paths/queries/fragments, field labels/types, attachment filename/MIME/size, delivery support, and counts. **Vault Material** is everything else: scalar values, usernames, passwords, TOTP data, notes, SSH keys, passkeys, and attachment bytes. Material is selectable for a one-shot run but is never readable as a tool result.

Broker and child output is finite and fail-closed. Malformed CLI JSON, output overflow, invalid/incompatible CLI, stale handles, expired tokens, locked/unavailable Keychain, cancelled prompts, socket/broker crashes, child failures, and partial attachment streams produce short non-secret error codes such as `invalid_cli_json`, `keychain_unavailable`, `invalid_handle`, `output_overflow`, `run_failed`, or `cleanup_partial`. Partial JSON is never parsed or returned.

## Cooperative CLI guard and limits

The extension uses Pi's documented `tool_call` event to best-effort block obvious agent commands through `bash`, including direct `bw`/`bitwarden-cli`/common path forms, `sudo`, `env`, `command`, and `npx`, `npm exec`, `pnpm exec`/`dlx`, and `yarn exec`/`dlx` wrappers for `get`, `list`, `export`, `serve`, `login`, and `unlock`. Help/version forms remain allowed. The guard is cooperative, bypassable, and is **not** an OS sandbox or enforcement boundary. It does not inspect or block `vault_run`; broker-owned direct `bw` children therefore continue to work. Deliberate host-process inspection, direct CLI use outside the Pi event path, UI phishing, arbitrary transformations, and command-driven exfiltration are out of scope.

## macOS and TUI requirements

The secure prompt is a masked custom Pi TUI component. A real interactive TUI and an unlocked macOS login Keychain are required for setup, configuration, and forget confirmation. Keep the Keychain unlocked for unattended unlock. RPC may expose ordinary Pi UI protocol behavior, but this extension deliberately refuses lifecycle operations outside `ctx.mode === "tui"`. No real Keychain or Bitwarden account is needed by the disposable tests; they inject fake adapters, Keychain objects, children, and temporary profiles.

## Troubleshooting

* **`ui_unavailable` / lifecycle refuses to run:** start Pi in its supported TUI mode; do not use print/JSON/RPC for setup, config, or forget.
* **`keychain_unavailable`:** unlock the macOS login Keychain and verify the installed native keyring package can load. An invalid stored credential is deleted; transient/network errors retain it for recovery.
* **`cli_unavailable` or `cli_error`:** install a compatible `bw`, keep it on `PATH`, and retry. Broker-owned children receive only a minimal environment plus the dedicated profile and private session.
* **`invalid_cli_json` / `output_overflow`:** the CLI response was malformed or exceeded the finite private bound; no partial response is used. Retry after checking the CLI version and vault size.
* **`invalid_handle` / `invalid_cursor`:** lock, expiry, reconfiguration, forget, broker restart, or snapshot eviction invalidated it; list/search again.
* **`host_key_changed` / `host_key_unavailable`:** the remote host key changed, or private trust state is malformed, insecure, full, or unwritable. The handshake is rejected before authentication. After verifying host identity out of band, deleting only the broker runtime's `known_hosts.json` resets trust.
* **`auth_failed` / `timed_out`:** SSH authentication was rejected or the connection timed out; check key, passphrase, host, and network availability.
* **`cleanup_partial`:** forget still invalidated memory leases and attempted every safe cleanup step. Check only the dedicated fixture/profile and Keychain entry, then retry from a TUI if appropriate; never delete unrelated profile data.
* **`config_recovery`:** configuration may have committed before its local acknowledgement was delivered. The client replays a bounded request identifier without repeating the replacement; if that also fails, retry `/vault-config` from the TUI. Config acknowledgements are operation receipts, not current lifecycle status: lock, forget, or a later replacement tombstones older IDs, so stale replays return `config_recovery` and never resurrect a profile. This code and its guidance contain no server account, credential, session, or material data.
* **stale socket/startup lock or broker crash:** retry a mediated request. Private runtime directory permissions, stale sockets, and dead startup locks are recovered fail-closed. Replacement has no backup directory: a post-Keychain-delete crash leaves only credential-less dedicated profile state for TUI recovery.
* **cancelled prompt or child/source failure:** no credential is persisted by Pi; retry. Attachment streams are backpressured, bounded, and terminated on source/target failure or timeout.

## Package maintenance and verification

Runtime dependencies belong in `dependencies`, not only `devDependencies`; `@napi-rs/keyring` and `ssh2` are exactly pinned in `package.json` and `package-lock.json`, and `extensions/vault/index.ts` is registered in the `pi` manifest. Use `npm ci` for a reproducible install, `npm test` for the full suite, and `./install.sh` for the normal local package installation. Reload behavior on a supported installed macOS Pi and actual TUI rendering/confirmation remain human checks; automated tests use isolated fake adapters and TUI harnesses only.
