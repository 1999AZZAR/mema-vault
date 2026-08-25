#!/usr/bin/env python3
import argparse
import base64
import getpass
import json
import os
import shutil
import sqlite3
import subprocess
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
EXPORT_SALT = b"mema-vault-export-v1"
WARN_DAYS = 90


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


def get_export_fernet(master_key=None):
    return derive_fernet(master_key or get_master_key(), EXPORT_SALT)


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
        cols = {row[1] for row in connection.execute("PRAGMA table_info(credentials)")}
        if "updated_at" not in cols:
            connection.execute("ALTER TABLE credentials ADD COLUMN updated_at TEXT")
        if "created_at" not in cols:
            connection.execute("ALTER TABLE credentials ADD COLUMN created_at TEXT")


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


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
    now = _now_iso()
    with database() as connection:
        connection.execute(
            "INSERT INTO credentials (service, username, encrypted_password, meta, updated_at, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(service) DO UPDATE SET "
            "username=excluded.username, encrypted_password=excluded.encrypted_password, "
            "meta=excluded.meta, updated_at=excluded.updated_at",
            (service, username, encrypted, meta, now, now),
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


def list_credentials(json_output=False, warn_days=WARN_DAYS):
    fernet = get_fernet()
    with database() as connection:
        validate_key(connection, fernet)
        rows = connection.execute(
            "SELECT service, username, updated_at FROM credentials ORDER BY service"
        ).fetchall()
    if json_output:
        data = []
        for service, username, updated_at in rows:
            entry = {"service": service, "username": username}
            if updated_at:
                entry["updated_at"] = updated_at
                try:
                    dt = datetime.fromisoformat(updated_at)
                    age_days = (datetime.now(timezone.utc) - dt).days
                    entry["age_days"] = age_days
                    if age_days > warn_days:
                        entry["stale"] = True
                except Exception:
                    pass
            data.append(entry)
        print(json.dumps(data if data else [], indent=2))
        return
    print("Vault Contents:")
    now = datetime.now(timezone.utc)
    for service, username, updated_at in rows:
        line = f"- {service} (User: {username})"
        if updated_at:
            try:
                dt = datetime.fromisoformat(updated_at)
                age = (now - dt).days
                line += f"  updated {age}d ago"
                if age > warn_days:
                    line += f"  [warn: >{warn_days}d, consider rotation]"
            except Exception:
                pass
        print(line)


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
            now = _now_iso()
            updates = [
                (new_fernet.encrypt(old_fernet.decrypt(token.encode())).decode(), now, row_id)
                for row_id, token in rows
            ]
            connection.executemany(
                "UPDATE credentials SET encrypted_password = ?, updated_at = ? WHERE id = ?", updates
            )
    except Exception:
        shutil.copy2(backup_path, DB_PATH)
        DB_PATH.chmod(0o600)
        raise
    print(f"Rotated {len(rows)} credentials. Backup: {backup_path}")


def verify_vault():
    fernet = get_fernet()
    with database() as connection:
        validate_key(connection, fernet)
        count = connection.execute("SELECT count(*) FROM credentials").fetchone()[0]
    print(f"OK: master key valid, {count} credential(s), salt OK")
    return 0


def env_exec(service, env_var, command):
    if not command:
        raise VaultError("env: no command provided after --")
    if command[0] == "--":
        command = command[1:]
    if not command:
        raise VaultError("env: no command provided after --")
    with database() as connection:
        row = connection.execute(
            "SELECT encrypted_password FROM credentials WHERE service = ?", (service,)
        ).fetchone()
    if not row:
        raise VaultError(f"credential not found: {service}")
    password = get_fernet().decrypt(row[0].encode()).decode()
    var_name = env_var
    if not var_name:
        var_name = service.upper().replace("-", "_").replace(" ", "_").replace("/", "_")
        var_name = "".join(c if c.isalnum() or c == "_" else "_" for c in var_name)
        if not var_name or var_name[0].isdigit():
            var_name = f"SVC_{var_name}"
    env = os.environ.copy()
    env[var_name] = password
    result = subprocess.run(command, env=env)
    sys.exit(result.returncode)


def export_vault(out_path, fmt="enc"):
    fernet = get_fernet()
    export_fernet = get_export_fernet()
    with database() as connection:
        validate_key(connection, fernet)
        rows = connection.execute(
            "SELECT service, username, encrypted_password, meta, updated_at, created_at FROM credentials ORDER BY service"
        ).fetchall()
    creds = []
    for service, username, enc, meta, updated_at, created_at in rows:
        password = fernet.decrypt(enc.encode()).decode()
        creds.append(
            {
                "service": service,
                "username": username,
                "password": password,
                "meta": meta or "",
                "updated_at": updated_at,
                "created_at": created_at,
            }
        )
    payload = json.dumps(
        {"version": 1, "exported_at": _now_iso(), "credentials": creds}, ensure_ascii=False
    ).encode()
    token = export_fernet.encrypt(payload)
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(token)
    out_path.chmod(0o600)
    print(f"Exported {len(creds)} credential(s) to {out_path} (encrypted, 0600)")


def import_vault(in_path, mode="merge"):
    in_path = Path(in_path)
    if not in_path.is_file():
        raise VaultError(f"import file not found: {in_path}")
    export_fernet = get_export_fernet()
    local_fernet = get_fernet()
    token = in_path.read_bytes().strip()
    try:
        payload = export_fernet.decrypt(token)
    except InvalidToken:
        raise VaultError("invalid master key for import file or corrupted file")
    data = json.loads(payload.decode())
    creds = data.get("credentials", [])
    if not isinstance(creds, list):
        raise VaultError("invalid import file format")
    with database() as connection:
        if mode == "replace":
            connection.execute("DELETE FROM credentials")
        count = 0
        for c in creds:
            service = c.get("service")
            username = c.get("username", "")
            password = c.get("password")
            meta = c.get("meta", "")
            updated_at = c.get("updated_at") or _now_iso()
            created_at = c.get("created_at") or updated_at
            if not service or password is None:
                continue
            enc = local_fernet.encrypt(password.encode()).decode()
            connection.execute(
                "INSERT INTO credentials (service, username, encrypted_password, meta, updated_at, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(service) DO UPDATE SET "
                "username=excluded.username, encrypted_password=excluded.encrypted_password, "
                "meta=excluded.meta, updated_at=excluded.updated_at",
                (service, username, enc, meta, updated_at, created_at),
            )
            count += 1
    print(f"Imported {count} credential(s) from {in_path} (mode={mode})")


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

    list_parser = subparsers.add_parser("list")
    list_parser.add_argument("--json", action="store_true", help="output as JSON")
    list_parser.add_argument("--warn-days", type=int, default=WARN_DAYS, help="stale threshold in days")

    delete_parser = subparsers.add_parser("delete")
    delete_parser.add_argument("service")

    rotate_parser = subparsers.add_parser("rotate-key")
    rotate_parser.add_argument("--new-key-stdin", action="store_true")

    subparsers.add_parser("verify")

    env_parser = subparsers.add_parser("env", help="run command with secret as env var")
    env_parser.add_argument("service", help="service name to inject")
    env_parser.add_argument("--env", dest="env_var", default=None, help="env var name (default: SERVICE uppercased)")
    env_parser.add_argument("command", nargs=argparse.REMAINDER, help="command after --")

    export_parser = subparsers.add_parser("export", help="export vault to encrypted file")
    export_parser.add_argument("--out", required=True, type=Path, help="output file path")
    export_parser.add_argument("--format", choices=["enc"], default="enc", help="export format")

    import_parser = subparsers.add_parser("import", help="import vault from encrypted file")
    import_parser.add_argument("--in", dest="input", required=True, type=Path, help="input file path")
    import_parser.add_argument("--mode", choices=["merge", "replace"], default="merge", help="merge or replace")

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
        list_credentials(json_output=args.json, warn_days=args.warn_days)
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
    elif args.command == "verify":
        verify_vault()
    elif args.command == "env":
        env_exec(args.service, args.env_var, args.command)
    elif args.command == "export":
        export_vault(args.out, args.format)
    elif args.command == "import":
        import_vault(args.input, args.mode)


if __name__ == "__main__":
    try:
        main()
    except InvalidToken:
        print("Error: invalid master key or corrupted credential", file=sys.stderr)
        sys.exit(2)
    except (OSError, sqlite3.Error, VaultError) as error:
        print(f"Error: {error}", file=sys.stderr)
        sys.exit(1)
