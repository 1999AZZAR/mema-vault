---
name: mema-vault
description: Secure local credential manager using authenticated Fernet encryption. Stores, retrieves, deletes, and rotates secrets using a mandatory master key. Use for managing API keys, database credentials, and other sensitive tokens.
metadata: {"openclaw":{"requires":{"env":["MEMA_VAULT_MASTER_KEY"]},"install":[{"id":"pip","kind":"exec","command":"pip install cryptography"}]}}
---

# Mema Vault

## Prerequisites
- **Agent Operations**: Set `MEMA_VAULT_MASTER_KEY` in the agent environment for noninteractive access.
- **User Operations**: When the environment variable is absent, commands securely prompt for the master key in a terminal.
- **Dependencies**: Requires `cryptography` Python package.

## Core Workflows

### 1. Store a Secret
Encrypt and save a new credential.
- **Interactive**: `python3 scripts/vault.py set <service> <user> [--meta "info"]`
- **Automation**: Send the secret through stdin with `--password-stdin`; never place secrets in command arguments.

### 2. Retrieve a Secret
Fetch a credential. By default, secrets are masked in output.
- **Usage**: `python3 scripts/vault.py get <service>`
- **Show Raw**: Use `--show` flag only when required for secure injection.
- **JSON**: Use `--json` (agents) with optional `--show` for full field access.

### 2b. Typed Records (card / address / note / apikey / generic)
Store structured secrets with per-type validation (card numbers get a
Luhn check, expiry must be `MM/YY`, CVV 3–4 digits, addresses require
street + city). Card numbers display masked except last 4.
- **Types**: `python3 scripts/vault.py types`
- **Card**: `python3 scripts/vault.py store bca --kind card --field cardholder="Name" --secret-field number --field expiry="08/28" --field cvv="123"`
- **Address (alamat)**: `python3 scripts/vault.py store rumah --kind address --fields-json '{"street":"Jl. Mawar 12","city":"Bandung","province":"Jawa Barat","postal":"40111","country":"ID"}'`
- **Note / API key / generic**: `--kind note --field body="..."`, `--kind apikey --password-stdin`, `--kind generic --field k=v`
- Prefer `--secret-field NAME` / `--password-stdin` over `--field` for secrets (keeps values out of process args / shell history).

### 3. List Credentials
- **Usage**: `python3 scripts/vault.py list` / `python3 scripts/vault.py list --json`
- Shows `age` and warns when `>90d` (override with `--warn-days N`). `--json` for agents.

### 4. Delete a Credential
Remove a credential permanently from the vault.
- **Usage**: `python3 scripts/vault.py delete <service>`

### 5. Verify Vault
Check master key + salt without exposing secrets.
- **Usage**: `python3 scripts/vault.py verify`

### 6. Run with Secret as Env Var
Inject a secret as an env var for one command, never prints it.
- **Usage**: `python3 scripts/vault.py env <service> [--env VAR_NAME] -- <cmd> [args...]`
- Example: `python3 scripts/vault.py env openai -- python3 my_agent.py` (var defaults to `OPENAI`)
- Example: `python3 scripts/vault.py env github --env GH_TOKEN -- gh auth login`

### 7. Export / Import (encrypted, portable)
Single encrypted blob (Fernet with PBKDF2 + fixed export salt, `0600`). Same master key decrypts it.
- **Export**: `python3 scripts/vault.py export --out /tmp/vault.enc`
- **Import merge**: `python3 scripts/vault.py import --in /tmp/vault.enc --mode merge`
- **Import replace**: `python3 scripts/vault.py import --in /tmp/vault.enc --mode replace`

### 8. Rotate the Master Key
- **Interactive**: `python3 scripts/vault.py rotate-key`
- **Agent Automation**: Set the old key in `MEMA_VAULT_MASTER_KEY` and the new key in `MEMA_VAULT_NEW_MASTER_KEY`.
- **Stdin Automation**: Send the new key through stdin with `--new-key-stdin`.
- Rotation creates a restricted database backup before updating any credential.

## Security Standards
- **Encryption**: Authenticated Fernet encryption with PBKDF2HMAC-SHA256 (480,000 iterations).
- **Masking**: Secrets are masked in standard logs/output unless explicitly requested.
- **Isolation**: The Master Key should never be stored in plaintext on disk.
- **Compatibility**: `MASTER_KEY` remains a deprecated fallback for existing installations.
- **Storage**: Override runtime paths with `MEMA_VAULT_DB_PATH` and `MEMA_VAULT_SALT_PATH` when packaging or sharing the skill.
- **Permissions**: Runtime database, salt, and rotation backups are restricted to owner-only (`0600`/`0700`).
