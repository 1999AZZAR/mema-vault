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
Fetch a credential. By default, the password is masked in output.
- **Usage**: `python3 scripts/vault.py get <service>`
- **Show Raw**: Use `--show` flag only when required for secure injection.

### 3. List Credentials
- **Usage**: `python3 scripts/vault.py list`

### 4. Delete a Credential
Remove a credential permanently from the vault.
- **Usage**: `python3 scripts/vault.py delete <service>`

### 5. Rotate the Master Key
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
- **Packaging**: Use `python3 scripts/package_skill.py [output.skill]`; it excludes `.env`, databases, salts, backups, and project memory.
