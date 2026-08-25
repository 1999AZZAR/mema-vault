#!/usr/bin/env python3
import argparse
import base64
import getpass
import os
import shutil
import sqlite3
import sys
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = Path(os.environ.get("MEMA_VAULT_DB_PATH", BASE_DIR / "data" / "vault.db"))
SALT_PATH = Path(os.environ.get("MEMA_VAULT_SALT_PATH", BASE_DIR / "data" / "salt.bin"))


class VaultError(Exception):
    pass


def get_master_key(variable="MEMA_VAULT_MASTER_KEY"):
    key = os.environ.get(variable)
    if key:
        return key.encode()
    if variable == "MEMA_VAULT_MASTER_KEY" and os.environ.get("MASTER_KEY"):
        print(
            "Warning: MASTER_KEY is deprecated; use MEMA_VAULT_MASTER_KEY.",
            file=sys.stderr,
        )
        return os.environ["MASTER_KEY"].encode()
    if sys.stdin.isatty():
        key = getpass.getpass("Master key: ")
        if key:
            return key.encode()
    raise VaultError(f"{variable} is not set")


def derive_fernet(master_key, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480_000,
    )
    return Fernet(base64.urlsafe_b64encode(kdf.derive(master_key)))


def get_fernet(master_key=None):
    if not SALT_PATH.exists():
        SALT_PATH.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        SALT_PATH.write_bytes(os.urandom(16))
    SALT_PATH.parent.chmod(0o700)
    SALT_PATH.chmod(0o600)
    salt = SALT_PATH.read_bytes()
    if len(salt) != 16:
        raise VaultError(f"invalid salt file: {SALT_PATH}")
    return derive_fernet(master_key or get_master_key(), salt)


def connect():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    DB_PATH.parent.chmod(0o700)
    connection = sqlite3.connect(DB_PATH)
    if DB_PATH.exists():
        DB_PATH.chmod(0o600)
    return connection


@contextmanager
def database():
    connection = connect()
    try:
        with connection:
            yield connection
    finally:
        connection.close()


def init_db():
    with database() as connection:
        connection.execute(
            "CREATE TABLE IF NOT EXISTS credentials ("
            "id INTEGER PRIMARY KEY, service TEXT UNIQUE, username TEXT, "
            "encrypted_password TEXT, meta TEXT)"
        )


def validate_key(connection, fernet):
    row = connection.execute(
        "SELECT encrypted_password FROM credentials LIMIT 1"
    ).fetchone()
    if row:
        fernet.decrypt(row[0].encode())


def read_secret(prompt, from_stdin=False):
    if from_stdin:
        value = sys.stdin.readline().rstrip("\r\n")
    elif sys.stdin.isatty():
        value = getpass.getpass(prompt)
    else:
        raise VaultError("no terminal available; use --password-stdin")
    if not value:
        raise VaultError("secret must not be empty")
    return value


def set_credential(service, username, password, meta=""):
    encrypted = get_fernet().encrypt(password.encode()).decode()
    with database() as connection:
        connection.execute(
            "INSERT INTO credentials (service, username, encrypted_password, meta) "
            "VALUES (?, ?, ?, ?) ON CONFLICT(service) DO UPDATE SET "
            "username=excluded.username, encrypted_password=excluded.encrypted_password, "
            "meta=excluded.meta",
            (service, username, encrypted, meta),
        )
    print(f"Stored: {service}")


def get_credential(service, show=False):
    with database() as connection:
        row = connection.execute(
            "SELECT service, username, encrypted_password, meta "
            "FROM credentials WHERE service = ?",
            (service,),
        ).fetchone()
    if not row:
        raise VaultError(f"credential not found: {service}")
    password = get_fernet().decrypt(row[2].encode()).decode()
    masked = (
        password[:2] + "*" * (len(password) - 4) + password[-2:]
        if len(password) > 4
        else "****"
    )
    print(f"Service: {row[0]}")
    print(f"User: {row[1]}")
    print(f"Pass: {password if show else masked}")
    print(f"Meta: {row[3]}")


def list_credentials():
    fernet = get_fernet()
    with database() as connection:
        validate_key(connection, fernet)
        rows = connection.execute(
            "SELECT service, username FROM credentials ORDER BY service"
        ).fetchall()
    print("Vault Contents:")
    for service, username in rows:
        print(f"- {service} (User: {username})")


def delete_credential(service):
    fernet = get_fernet()
    with database() as connection:
        validate_key(connection, fernet)
        cursor = connection.execute(
            "DELETE FROM credentials WHERE service = ?", (service,)
        )
    if not cursor.rowcount:
        raise VaultError(f"credential not found: {service}")
    print(f"Deleted: {service}")


def rotate_master_key(new_key):
    old_fernet = get_fernet()
    new_fernet = derive_fernet(new_key.encode(), SALT_PATH.read_bytes())
    backup_path = DB_PATH.with_name(
        f"{DB_PATH.name}.backup-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
    )
    shutil.copy2(DB_PATH, backup_path)
    backup_path.chmod(0o600)
    try:
        with database() as connection:
            rows = connection.execute(
                "SELECT id, encrypted_password FROM credentials"
            ).fetchall()
            updates = [
                (new_fernet.encrypt(old_fernet.decrypt(token.encode())).decode(), row_id)
                for row_id, token in rows
            ]
            connection.executemany(
                "UPDATE credentials SET encrypted_password = ? WHERE id = ?", updates
            )
    except Exception:
        shutil.copy2(backup_path, DB_PATH)
        DB_PATH.chmod(0o600)
        raise
    print(f"Rotated {len(rows)} credentials. Backup: {backup_path}")


def build_parser():
    parser = argparse.ArgumentParser(description="Mema Vault CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    set_parser = subparsers.add_parser("set")
    set_parser.add_argument("service")
    set_parser.add_argument("username")
    set_parser.add_argument("--meta", default="")
    set_parser.add_argument("--password-stdin", action="store_true")

    get_parser = subparsers.add_parser("get")
    get_parser.add_argument("service")
    get_parser.add_argument("--show", action="store_true", help="show raw password")

    subparsers.add_parser("list")

    delete_parser = subparsers.add_parser("delete")
    delete_parser.add_argument("service")

    rotate_parser = subparsers.add_parser("rotate-key")
    rotate_parser.add_argument("--new-key-stdin", action="store_true")
    return parser


def main():
    args = build_parser().parse_args()
    init_db()
    if args.command == "set":
        password = read_secret("Password: ", args.password_stdin)
        set_credential(args.service, args.username, password, args.meta)
    elif args.command == "get":
        get_credential(args.service, args.show)
    elif args.command == "list":
        list_credentials()
    elif args.command == "delete":
        delete_credential(args.service)
    elif args.command == "rotate-key":
        new_key = os.environ.get("MEMA_VAULT_NEW_MASTER_KEY")
        if not new_key:
            new_key = read_secret("New master key: ", args.new_key_stdin)
        if not args.new_key_stdin and "MEMA_VAULT_NEW_MASTER_KEY" not in os.environ:
            confirmation = getpass.getpass("Confirm new master key: ")
            if new_key != confirmation:
                raise VaultError("new master keys do not match")
        rotate_master_key(new_key)


if __name__ == "__main__":
    try:
        main()
    except InvalidToken:
        print("Error: invalid master key or corrupted credential", file=sys.stderr)
        sys.exit(2)
    except (OSError, sqlite3.Error, VaultError) as error:
        print(f"Error: {error}", file=sys.stderr)
        sys.exit(1)
