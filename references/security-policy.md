# Security Policy: Mema Vault

## Cryptography
- **Algorithm**: Authenticated Fernet encryption (AES-128-CBC with HMAC-SHA256).
- **Key Derivation**: PBKDF2HMAC-SHA256.
- **Iterations**: 480,000.
- **Salt**: Random 16-byte salt, stored in `data/salt.bin`.

## Storage
- **Primary Backend**: Local SQLite database (`data/vault.db` by default).
- **Persistence**: All encrypted credentials and metadata are stored locally in the workspace.
- **Permissions**: Runtime database, salt, and rotation backups are restricted to the owner.
- **Path Overrides**: `MEMA_VAULT_DB_PATH` and `MEMA_VAULT_SALT_PATH` can keep runtime data outside distributable skill files.
- **No External Dependencies**: This version does not use Redis or cloud storage to ensure zero-network footprint.

## Access Control
- **Master Key**: Required for all read/write operations. Agents use `MEMA_VAULT_MASTER_KEY`; terminal users are prompted when it is absent. `MASTER_KEY` is accepted only as a deprecated compatibility fallback.
- **Process Isolation**: Secrets are only decrypted in memory during the execution of the `vault` script.
- **Output Masking**: Passwords are masked unless the `--show` flag is explicitly provided.

## Logging & Auditing
- **Audit Output**: Successful mutations are reported to the console without secret values.
- **No Secret Logging**: The logic strictly prevents raw secrets from being written to any log file.

## Data Exposure
- Passwords are encrypted. Service names, usernames, and metadata remain plaintext in SQLite.
- Do not package or share `.env`, `data/vault.db`, database backups, or runtime salt files.
- `.gitignore` excludes `.env`, databases, salts, and backups.
