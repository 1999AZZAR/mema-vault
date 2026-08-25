import os
import sqlite3
import getpass
import shutil
from pathlib import Path
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import base64

BASE_DIR = Path("/home/azzar/.agents/skills/mema-vault")
LOCAL_DB = BASE_DIR / "data/vault.db"
LOCAL_SALT = BASE_DIR / "data/salt.bin"

OTHER_DB = BASE_DIR / "data/from-other/vault.db"
OTHER_SALT = BASE_DIR / "data/from-other/salt.bin"

def derive_fernet(master_key, salt_path):
    salt = salt_path.read_bytes()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480_000,
    )
    return Fernet(base64.urlsafe_b64encode(kdf.derive(master_key)))

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
        master_key_str = getpass.getpass("Enter master key (assuming same for both): ")
    
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

    with sqlite3.connect(LOCAL_DB) as local_conn, sqlite3.connect(OTHER_DB) as other_conn:
        # Verify local key
        local_row = local_conn.execute("SELECT encrypted_password FROM credentials LIMIT 1").fetchone()
        if local_row:
            try:
                local_fernet.decrypt(local_row[0].encode())
            except Exception:
                print("Error: Invalid master key for local vault.")
                return

        # Verify other key
        other_row = other_conn.execute("SELECT encrypted_password FROM credentials LIMIT 1").fetchone()
        if other_row:
            try:
                other_fernet.decrypt(other_row[0].encode())
            except Exception:
                print("Error: Invalid master key for 'from-other' vault.")
                return

        other_creds = other_conn.execute("SELECT service, username, encrypted_password, meta FROM credentials").fetchall()
        print(f"\nFound {len(other_creds)} credentials in 'from-other' vault.")

        updates = 0
        for service, username, enc_password, meta in other_creds:
            try:
                # Decrypt password from other vault
                plaintext_pass = other_fernet.decrypt(enc_password.encode())
                # Encrypt password for local vault
                new_enc_password = local_fernet.encrypt(plaintext_pass).decode()
                
                # Insert or replace into local vault
                local_conn.execute(
                    "INSERT INTO credentials (service, username, encrypted_password, meta) "
                    "VALUES (?, ?, ?, ?) ON CONFLICT(service) DO UPDATE SET "
                    "username=excluded.username, encrypted_password=excluded.encrypted_password, "
                    "meta=excluded.meta",
                    (service, username, new_enc_password, meta)
                )
                updates += 1
                print(f"[*] Merged: {service}")
            except Exception as e:
                print(f"[!] Failed to merge {service}: {e}")
                
        print(f"\nSuccessfully merged {updates} credentials into local vault.")
        print("\nIMPORTANT:")
        print("To make both machines have the same vault, you MUST copy BOTH of these files back to the other machine:")
        print(f"1. {LOCAL_DB}")
        print(f"2. {LOCAL_SALT}")
        print("Copying only the vault.db will result in decryption errors because the salts will mismatch.")

if __name__ == '__main__':
    main()
