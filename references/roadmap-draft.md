# Mema Vault — Enhancement Draft

> Status: draft for review. No code changes yet. Pick Phase 1 to implement first.

## Diagnosis

Strong: offline, zero-deps (cryptography only), simple mental model, good for solo + agents.
Gaps: manual sync is error-prone, no safe export, no `env` helper (users resort to `--show | awk`), plaintext service names leak inventory, single master key = single point of failure, no expiry/rotation nudge.

## Proposal — 3 Phases

### Phase 1 — Quick wins (1-2 days, no breaking change)

**1a. `vault verify` + `vault env`**
- `verify`: decrypts 1 row to confirm master key + salt match. Exit 0/2. For CI health checks.
- `env <service> -- <cmd>`: injects secret as env var for one command, never prints. Solves `--show` leakage.
  ```bash
  python3 scripts/vault.py env openai --env OPENAI_API_KEY -- python3 my_agent.py
  python3 scripts/vault.py env stripe -- python3 app.py  # defaults to SERVICE_API_KEY
  ```

**1b. Encrypted export / import**
- `export --out vault.enc --format enc` : single Fernet blob containing all rows (encrypted with current master key + salt). Safe to store in git/private gist.
- `import --in vault.enc --mode merge|replace` : decrypts with same master key, merges via `ON CONFLICT(service) DO UPDATE`.
- Replaces ad-hoc `cp vault.db + salt.bin` and fixes salt-coupling fragility.

**1c. Rotation & expiry warnings**
- Add `updated_at` column (auto on set/rotate). `list` shows `age` and warns `>90d`.
- `list --json` for agents.

### Phase 2 — Hardening (1 week, minor breaking opt-in)

**2a. OS keychain fallback**
- If `MEMA_VAULT_MASTER_KEY` absent and no TTY, try `keyring` (macOS Keychain / libsecret / WinCred). Falls back to prompt. Never writes key to disk.

**2b. Optional service-name encryption**
- New flag `MEMA_VAULT_ENCRYPT_NAMES=1` → encrypts `service`/`username`/`meta` with deterministic SIV or HMAC index. Default off (keeps `list` usable). Migration: `vault.py migrate --encrypt-names`.

**2c. Audit log**
- Append-only `vault.log` (service, action, timestamp, no secrets). For `rotate`/`delete` forensics.

### Phase 3 — Future (breaking, major version)

**3a. Argon2id KDF option** (keep PBKDF2 default for compat, add `--kdf argon2id` on init, store `kdf_params` in salt header).
**3b. Profiles** (`--profile work|personal` → separate `vault.db`/`salt.bin` pairs).
**3c. Shamir split** for master key recovery (2-of-3).

## Priority Matrix

| Feature | Value | Effort | Risk |
|---------|-------|--------|------|
| `env` helper | High | Low | Low |
| encrypted export/import | High | Low | Low |
| `verify` + expiry | Medium | Low | Low |
| keychain | Medium | Medium | Medium |
| encrypt names | Medium | Medium | High (search) |
| Argon2id | Low | High | Medium |

## Recommended Next Step

Implement Phase 1a+1b in one PR:
- Add `updated_at` migration, `verify`, `env`, `export`, `import` subcommands to `scripts/vault.py`
- Tests: temp vault round-trip for each command
- Docs: README Use Cases + CLI reference update

Want me to implement Phase 1 now? Reply `phase 1` and I will code it.
