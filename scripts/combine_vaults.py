"""Merge another mema-vault into the local one (typed-schema aware).

Re-encrypts every record (password + typed fields) from the "from-other"
vault with the local salt. Handles legacy (v1, login-only) databases as
well as typed (v2) databases.
"""
import os
import sqlite3
import getpass
from pathlib import Path
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet, InvalidToken
import base64

BASE_DIR = Path("/home/azzar/.agents/skills/mema-vault")
LOCAL_DB = BASE_DIR / "data/vault.db"
LOCAL_SALT = BASE_DIR / "data/salt.bin"

OTHER_DB = BASE_DIR / "data/from-other/vault.db"
OTHER_SALT = BASE_DIR / "data/from-other/salt.bin"


def derive_fernet(master_key, salt_path):
    try:
        salt = salt_path.read_bytes()
    except OSError as exc:
        raise RuntimeError(f"cannot read salt {salt_path}: {exc}")
    if len(salt) != 16:
        raise RuntimeError(f"invalid salt file: {salt_path}")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480_000,
    )
    return Fernet(base64.urlsafe_b64encode(kdf.derive(master_key)))


def _columns(connection, table):
    return {
        row[1] for row in connection.execute(f"PRAGMA table_info({table})")
    }


def _verify(fernet, connection, label):
    try:
        verifier = connection.execute(
            "SELECT value FROM vault_meta WHERE key = 'key_verifier'"
        ).fetchone()
    except sqlite3.Error:
        verifier = None
    if verifier:
        try:
            fernet.decrypt(verifier[0].encode())
        except InvalidToken:
            print(f"Error: Invalid master key for {label} vault.")
            return False
        return True
    try:
        row = connection.execute(
            "SELECT encrypted_password, encrypted_fields FROM credentials LIMIT 1"
        ).fetchone() if "credentials" in {
            r[0] for r in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        } else None
    except sqlite3.Error as exc:
        print(f"Error: cannot read {label} vault: {exc}")
        return False
    if row:
        for token in row:
            if token:
                try:
                    fernet.decrypt(token.encode())
                except InvalidToken:
                    print(f"Error: Invalid master key for {label} vault.")
                    return False
    return True


def main():
    print("Mema Vault Combiner")
    print("===================")

    if not LOCAL_DB.exists() or not LOCAL_SALT.exists():
        print(f"Error: Local vault not found at {LOCAL_DB}")
        return

    if not OTHER_DB.exists() or not OTHER_SALT.exists():
        print(f"Error: Other vault not found at {OTHER_DB}")
        return

    master_key_str = os.environ.get("MEMA_VAULT_MASTER_KEY")
    if not master_key_str:
        try:
            master_key_str = getpass.getpass(
                "Enter master key (assuming same for both): "
            )
        except (OSError, ValueError, KeyboardInterrupt) as exc:
            print(f"Error: cannot read master key: {exc}")
            return

    if not master_key_str:
        print("Error: Master key cannot be empty.")
        return

    master_key = master_key_str.encode()

    try:
        local_fernet = derive_fernet(master_key, LOCAL_SALT)
        other_fernet = derive_fernet(master_key, OTHER_SALT)
    except Exception as e:
        print(f"Error deriving keys: {e}")
        return

    try:
        local_conn = sqlite3.connect(LOCAL_DB)
        other_conn = sqlite3.connect(OTHER_DB)
    except sqlite3.Error as exc:
        print(f"Error: cannot open vaults: {exc}")
        return

    with local_conn, other_conn:
        if not _verify(local_fernet, local_conn, "local"):
            return
        if not _verify(other_fernet, other_conn, "from-other"):
            return

        other_cols = _columns(other_conn, "credentials")
        local_cols = _columns(local_conn, "credentials")
        for required in ("service", "username", "encrypted_password"):
            if required not in other_cols:
                print(f"Error: 'from-other' vault is missing column {required}.")
                return
        if "kind" not in local_cols or "encrypted_fields" not in local_cols:
            print("Error: local vault uses an old schema. "
                  "Run `python3 scripts/vault.py verify` first to migrate.")
            return

        select_cols = (
            "service, username, encrypted_password, meta, "
            + ("kind" if "kind" in other_cols else "'login'")
            + ", "
            + ("encrypted_fields" if "encrypted_fields" in other_cols else "''")
        )
        try:
            other_creds = other_conn.execute(
                f"SELECT {select_cols} FROM credentials"
            ).fetchall()
        except sqlite3.Error as exc:
            print(f"Error: cannot read 'from-other' vault: {exc}")
            return
        print(f"\nFound {len(other_creds)} credentials in 'from-other' vault.")

        # Ensure local verifier exists so merged vault stays openable when empty.
        try:
            has_verifier = local_conn.execute(
                "SELECT 1 FROM vault_meta WHERE key = 'key_verifier'"
            ).fetchone()
            if not has_verifier:
                local_conn.execute(
                    "INSERT INTO vault_meta (key, value) VALUES ('key_verifier', ?)",
                    (local_fernet.encrypt(b"mema-vault-verifier-v1").decode(),),
                )
        except sqlite3.Error:
            pass

        updates = 0
        for service, username, enc_password, meta, kind, enc_fields in other_creds:
            if not service:
                print("[!] Skipping record with empty service name")
                continue
            try:
                # Decrypt from other vault (raw bytes stay opaque — any type works).
                plaintext_pass = other_fernet.decrypt(enc_password.encode()) \
                    if enc_password else b""
                plaintext_fields = other_fernet.decrypt(enc_fields.encode()) \
                    if enc_fields else b""
                # Re-encrypt for local vault.
                new_enc_password = local_fernet.encrypt(plaintext_pass).decode() \
                    if plaintext_pass else ""
                new_enc_fields = local_fernet.encrypt(plaintext_fields).decode() \
                    if plaintext_fields else ""

                # Insert or replace into local vault
                local_conn.execute(
                    "INSERT INTO credentials (service, kind, username, "
                    "encrypted_password, encrypted_fields, meta) "
                    "VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(service) DO UPDATE SET "
                    "kind=excluded.kind, username=excluded.username, "
                    "encrypted_password=excluded.encrypted_password, "
                    "encrypted_fields=excluded.encrypted_fields, "
                    "meta=excluded.meta",
                    (service, kind or "login", username or "",
                     new_enc_password, new_enc_fields, meta or ""),
                )
                updates += 1
                print(f"[*] Merged: {service} [{kind or 'login'}]")
            except InvalidToken:
                print(f"[!] Failed to merge {service}: decryption failed "
                      f"(wrong key or corrupted record)")
            except Exception as e:
                print(f"[!] Failed to merge {service}: {e}")

        print(f"\nSuccessfully merged {updates} credentials into local vault.")
        print("\nIMPORTANT:")
        print(
            "To make both machines have the same vault, you MUST copy BOTH of these files back to the other machine:"
        )
        print(f"1. {LOCAL_DB}")
        print(f"2. {LOCAL_SALT}")
        print(
            "Copying only the vault.db will result in decryption errors because the salts will mismatch."
        )


if __name__ == "__main__":
    main()
