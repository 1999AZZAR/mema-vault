#!/usr/bin/env python3
"""Mema Vault - hardened local credential manager.

Supports typed records (login, card, address, note, apikey, generic) with
per-kind validation, while keeping the legacy login (service/username/
password/meta) flow fully backward compatible.

Security: Fernet (PBKDF2HMAC-SHA256, 480k iterations) + random 16-byte salt.
Service/username/meta stay plaintext; passwords and typed fields are encrypted.
"""
import argparse
import base64
import difflib
import getpass
import json
import os
import re
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
EXPORT_VERSION = 2
WARN_DAYS = 90
VERIFIER_PLAINTEXT = b"mema-vault-verifier-v1"

# Hardening limits
MAX_SERVICE_LEN = 128
MAX_USERNAME_LEN = 256
MAX_META_LEN = 4096
MAX_FIELD_VALUE_LEN = 16_384
MAX_FIELDS_TOTAL_LEN = 65_536
MIN_MASTER_KEY_LEN = 8
RECOMMENDED_MASTER_KEY_LEN = 12
SQLITE_TIMEOUT = 10.0

# Restrictive creation mask for db/salt/backups/exports (0600/0700).
os.umask(0o077)


class VaultError(Exception):
    pass


# ---------------------------------------------------------------------------
# Master key / crypto
# ---------------------------------------------------------------------------

def _check_key_strength(key_str, variable="MEMA_VAULT_MASTER_KEY"):
    if not key_str or not key_str.strip():
        raise VaultError(f"{variable} must not be empty")
    if len(key_str) < MIN_MASTER_KEY_LEN:
        raise VaultError(
            f"{variable} too short ({len(key_str)} chars); "
            f"minimum {MIN_MASTER_KEY_LEN} characters"
        )
    if len(key_str) > 512:
        raise VaultError(f"{variable} too long (max 512 characters)")
    if len(key_str) < RECOMMENDED_MASTER_KEY_LEN:
        print(
            f"Warning: {variable} is short ({len(key_str)} chars); "
            f"use >= {RECOMMENDED_MASTER_KEY_LEN} characters.",
            file=sys.stderr,
        )


def get_master_key(variable="MEMA_VAULT_MASTER_KEY"):
    key = os.environ.get(variable)
    if key:
        _check_key_strength(key, variable)
        return key.encode()
    if variable == "MEMA_VAULT_MASTER_KEY" and os.environ.get("MASTER_KEY"):
        print(
            "Warning: MASTER_KEY is deprecated; use MEMA_VAULT_MASTER_KEY.",
            file=sys.stderr,
        )
        _check_key_strength(os.environ["MASTER_KEY"], "MASTER_KEY")
        return os.environ["MASTER_KEY"].encode()
    if sys.stdin.isatty():
        key = getpass.getpass("Master key: ")
        if key:
            _check_key_strength(key, variable)
            return key.encode()
    raise VaultError(f"{variable} is not set")


def derive_fernet(master_key, salt):
    if not isinstance(master_key, (bytes, bytearray)) or not master_key:
        raise VaultError("invalid master key material")
    if not isinstance(salt, (bytes, bytearray)) or len(salt) < 16:
        raise VaultError("invalid salt")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=bytes(salt),
        iterations=480_000,
    )
    return Fernet(base64.urlsafe_b64encode(kdf.derive(bytes(master_key))))


def _read_salt():
    try:
        salt = SALT_PATH.read_bytes()
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise VaultError(f"cannot read salt file {SALT_PATH}: {exc}")
    if len(salt) != 16:
        raise VaultError(
            f"invalid salt file: {SALT_PATH} (expected 16 bytes, got {len(salt)}). "
            "Do NOT delete it — back up vault.db + salt.bin first; "
            "losing the salt makes passwords unrecoverable."
        )
    return salt


def get_fernet(master_key=None):
    if not SALT_PATH.exists():
        try:
            SALT_PATH.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        except OSError as exc:
            raise VaultError(f"cannot create vault dir: {exc}")
        try:
            SALT_PATH.parent.chmod(0o700)
        except OSError:
            pass
        try:
            SALT_PATH.write_bytes(os.urandom(16))
        except OSError as exc:
            raise VaultError(f"cannot write salt file: {exc}")
    else:
        try:
            SALT_PATH.parent.chmod(0o700)
        except OSError:
            pass
    try:
        SALT_PATH.chmod(0o600)
    except OSError:
        pass
    salt = _read_salt()
    try:
        return derive_fernet(master_key or get_master_key(), salt)
    except (VaultError, ValueError) as exc:
        raise VaultError(f"cannot derive key: {exc}")


def get_export_fernet(master_key=None):
    return derive_fernet(master_key or get_master_key(), EXPORT_SALT)


# ---------------------------------------------------------------------------
# DB layer
# ---------------------------------------------------------------------------

def connect():
    try:
        DB_PATH.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    except OSError as exc:
        raise VaultError(f"cannot create vault dir: {exc}")
    try:
        DB_PATH.parent.chmod(0o700)
    except OSError:
        pass
    try:
        connection = sqlite3.connect(str(DB_PATH), timeout=SQLITE_TIMEOUT)
    except sqlite3.Error as exc:
        raise VaultError(f"cannot open vault database: {exc}")
    try:
        connection.execute(f"PRAGMA busy_timeout = {int(SQLITE_TIMEOUT * 1000)}")
    except sqlite3.Error:
        pass
    if DB_PATH.exists():
        try:
            DB_PATH.chmod(0o600)
        except OSError:
            pass
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
        try:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS credentials ("
                "id INTEGER PRIMARY KEY, service TEXT UNIQUE NOT NULL, "
                "username TEXT DEFAULT '', "
                "encrypted_password TEXT DEFAULT '', meta TEXT DEFAULT '')"
            )
            cols = {
                row[1]
                for row in connection.execute("PRAGMA table_info(credentials)")
            }
            for col, ddl in (
                ("updated_at", "ALTER TABLE credentials ADD COLUMN updated_at TEXT"),
                ("created_at", "ALTER TABLE credentials ADD COLUMN created_at TEXT"),
                ("kind", "ALTER TABLE credentials ADD COLUMN kind TEXT DEFAULT 'login'"),
                (
                    "encrypted_fields",
                    "ALTER TABLE credentials ADD COLUMN encrypted_fields TEXT DEFAULT ''",
                ),
            ):
                if col not in cols:
                    connection.execute(ddl)
            # Backfill kind for legacy rows.
            connection.execute(
                "UPDATE credentials SET kind = 'login' WHERE kind IS NULL OR kind = ''"
            )
            connection.execute(
                "CREATE TABLE IF NOT EXISTS vault_meta ("
                "key TEXT PRIMARY KEY, value TEXT NOT NULL)"
            )
        except sqlite3.Error as exc:
            raise VaultError(f"cannot initialize vault database: {exc}")


def _get_verifier_token(connection):
    try:
        row = connection.execute(
            "SELECT value FROM vault_meta WHERE key = 'key_verifier'"
        ).fetchone()
    except sqlite3.Error as exc:
        raise VaultError(f"cannot read key verifier: {exc}")
    return row[0] if row else None


def ensure_verifier(connection, fernet):
    """Create-or-check the key verifier.

    Fixes the empty-vault hole: previously a wrong master key was accepted
    when the vault had zero rows because validation only trial-decrypted a
    credential row. The verifier makes wrong keys fail even on empty vaults.
    """
    token = _get_verifier_token(connection)
    if token is None:
        try:
            token = fernet.encrypt(VERIFIER_PLAINTEXT).decode()
            connection.execute(
                "INSERT INTO vault_meta (key, value) VALUES ('key_verifier', ?)",
                (token,),
            )
        except sqlite3.Error as exc:
            raise VaultError(f"cannot store key verifier: {exc}")
        return
    # NOTE: InvalidToken intentionally propagates (wrong master key),
    # keeping Fernet auth-failure semantics for callers/tests.
    if fernet.decrypt(token.encode()) != VERIFIER_PLAINTEXT:
        raise VaultError("invalid master key (verifier mismatch)")


def validate_key(connection, fernet):
    try:
        ensure_verifier(connection, fernet)
    except InvalidToken:
        raise
    except VaultError:
        raise
    except Exception as exc:
        raise VaultError(f"key validation failed: {exc}") from exc
    try:
        row = connection.execute(
            "SELECT encrypted_password, encrypted_fields FROM credentials LIMIT 1"
        ).fetchone()
    except sqlite3.Error as exc:
        raise VaultError(f"cannot validate key: {exc}")
    if row:
        for token in row:
            if token:
                fernet.decrypt(token.encode())


def _decrypt_text(fernet, token, what="credential"):
    if not token:
        return ""
    # NOTE: InvalidToken propagates untouched (wrong key / tampered data).
    try:
        return fernet.decrypt(token.encode()).decode()
    except (UnicodeDecodeError, ValueError) as exc:
        raise VaultError(f"corrupted {what}: {exc}") from exc


def _decrypt_fields(fernet, token):
    raw = _decrypt_text(fernet, token, "fields")
    if not raw:
        return {}
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise VaultError(f"corrupted fields payload: {exc}") from exc
    if not isinstance(data, dict):
        raise VaultError("corrupted fields payload (not an object)")
    return data


# ---------------------------------------------------------------------------
# Validation: names + typed kinds
# ---------------------------------------------------------------------------

_SERVICE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\-/ @+]{0,127}$")

KINDS = ("login", "apikey", "card", "address", "note", "generic")

# kind -> {required, optional, sensitive}. Sensitive fields are masked unless --show.
KIND_SCHEMAS = {
    "login": {
        "required": [],
        "optional": ["username", "password"],
        "sensitive": ["password"],
        "help": "classic service login (uses username + password)",
    },
    "apikey": {
        "required": [],
        "optional": ["key", "username", "note"],
        "sensitive": ["key"],
        "help": "API token/key, e.g. fields: key, note",
    },
    "card": {
        "required": ["number", "expiry"],
        "optional": ["cardholder", "cvv", "pin", "note"],
        "sensitive": ["number", "cvv", "pin"],
        "help": "credit/debit card: number (Luhn), expiry MM/YY[YY], cvv 3-4 digits",
    },
    "address": {
        "required": ["street", "city"],
        "optional": ["name", "province", "postal", "country", "phone", "note"],
        "sensitive": [],
        "help": "alamat: street, city required; province/postal/country/phone optional",
    },
    "note": {
        "required": ["body"],
        "optional": ["title"],
        "sensitive": [],
        "help": "secure note: body required",
    },
    "generic": {
        "required": [],
        "optional": [],
        "sensitive": [],
        "help": "arbitrary encrypted key=value fields (free-form)",
    },
}


def validate_service(service):
    if service is None:
        raise VaultError("service must not be empty")
    service = str(service).strip()
    if not service:
        raise VaultError("service must not be empty")
    if len(service) > MAX_SERVICE_LEN:
        raise VaultError(f"service too long (max {MAX_SERVICE_LEN} chars)")
    if "\x00" in service or "\n" in service or "\r" in service:
        raise VaultError("service contains invalid characters")
    return service


def validate_username(username):
    username = "" if username is None else str(username)
    if len(username) > MAX_USERNAME_LEN:
        raise VaultError(f"username too long (max {MAX_USERNAME_LEN} chars)")
    if "\x00" in username or "\n" in username or "\r" in username:
        raise VaultError("username contains invalid characters")
    return username


def validate_meta(meta):
    meta = "" if meta is None else str(meta)
    if len(meta) > MAX_META_LEN:
        raise VaultError(f"meta too long (max {MAX_META_LEN} chars)")
    if "\x00" in meta:
        raise VaultError("meta contains invalid characters")
    return meta


def validate_kind(kind):
    kind = (kind or "login").strip().lower()
    if kind not in KINDS:
        suggestion = difflib.get_close_matches(kind, list(KINDS), n=1)
        hint = f" (did you mean '{suggestion[0]}'?)" if suggestion else ""
        raise VaultError(f"unknown kind '{kind}'{hint}. Valid: {', '.join(KINDS)}")
    return kind


def _luhn_ok(number):
    digits = re.sub(r"[\s\-]", "", number or "")
    if not digits.isdigit() or not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = ord(ch) - 48
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _validate_expiry(expiry):
    m = re.fullmatch(r"\s*(0[1-9]|1[0-2])\s*/\s*(\d{2}|\d{4})\s*", expiry or "")
    if not m:
        raise VaultError("expiry must be MM/YY or MM/YYYY (e.g. 08/27)")
    month = int(m.group(1))
    year = int(m.group(2))
    if year < 100:
        year += 2000
    now = datetime.now(timezone.utc)
    if (year, month) < (now.year, now.month):
        print(f"Warning: card expiry {expiry.strip()} is in the past.", file=sys.stderr)
    return f"{month:02d}/{str(year)[2:]}"


def validate_fields(kind, fields):
    """Validate + normalize typed fields. Returns a clean dict."""
    kind = validate_kind(kind)
    if not isinstance(fields, dict):
        raise VaultError("fields must be an object")
    schema = KIND_SCHEMAS[kind]
    cleaned = {}
    for key, value in fields.items():
        if not isinstance(key, str) or not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_\-]{0,63}", key):
            raise VaultError(f"invalid field name: {key!r}")
        value = "" if value is None else str(value)
        if len(value) > MAX_FIELD_VALUE_LEN:
            raise VaultError(f"field '{key}' too long (max {MAX_FIELD_VALUE_LEN} chars)")
        if "\x00" in value:
            raise VaultError(f"field '{key}' contains invalid characters")
        cleaned[key.strip()] = value.strip() if key != "body" else value

    if kind != "generic":
        allowed = set(schema["required"]) | set(schema["optional"])
        # login/apikey accept username/password aliases into fields too — be lenient.
        unknown = [k for k in cleaned if k not in allowed]
        if unknown:
            raise VaultError(
                f"kind '{kind}' does not accept field(s): {', '.join(unknown)}. "
                f"Allowed: {', '.join(schema['required'] + schema['optional']) or '(none)'}"
            )
        missing = [k for k in schema["required"] if not cleaned.get(k)]
        if missing:
            raise VaultError(
                f"kind '{kind}' missing required field(s): {', '.join(missing)}"
            )
    if len(json.dumps(cleaned, ensure_ascii=False)) > MAX_FIELDS_TOTAL_LEN:
        raise VaultError("fields payload too large (max 64KB)")

    if kind == "card":
        number = re.sub(r"[\s\-]", "", cleaned.get("number", ""))
        if not _luhn_ok(number):
            raise VaultError("card number failed Luhn check (13-19 digits)")
        cleaned["number"] = number
        cleaned["expiry"] = _validate_expiry(cleaned.get("expiry", ""))
        cvv = cleaned.get("cvv", "")
        if cvv and not re.fullmatch(r"\d{3,4}", cvv):
            raise VaultError("cvv must be 3-4 digits")
        pin = cleaned.get("pin", "")
        if pin and not re.fullmatch(r"\d{4,8}", pin):
            raise VaultError("pin must be 4-8 digits")
    elif kind == "address":
        for f in ("street", "city", "province", "postal", "country", "phone", "name"):
            if f in cleaned and len(cleaned[f]) > 512:
                raise VaultError(f"address field '{f}' too long (max 512 chars)")
        phone = cleaned.get("phone", "")
        if phone and not re.fullmatch(r"[+\d][\d\s\-().]{5,31}", phone):
            raise VaultError("phone looks invalid")
    elif kind == "note":
        if len(cleaned.get("body", "")) > MAX_FIELD_VALUE_LEN:
            raise VaultError("note body too long")
    return cleaned


def parse_field_args(field_list, fields_json):
    """Combine repeated --field k=v with --fields-json into one dict."""
    merged = {}
    if fields_json:
        try:
            parsed = json.loads(fields_json)
        except json.JSONDecodeError as exc:
            raise VaultError(f"invalid --fields-json: {exc}") from exc
        if not isinstance(parsed, dict):
            raise VaultError("--fields-json must be a JSON object")
        merged.update({str(k): v for k, v in parsed.items()})
    for item in field_list or []:
        if "=" not in item:
            raise VaultError(
                f"invalid --field {item!r}; expected KEY=VALUE"
            )
        key, value = item.split("=", 1)
        key = key.strip()
        if not key:
            raise VaultError(f"invalid --field {item!r}; empty key")
        merged[key] = value
    return merged


# ---------------------------------------------------------------------------
# Masking / display
# ---------------------------------------------------------------------------

def mask_password(password):
    if len(password) > 4:
        return password[:2] + "*" * (len(password) - 4) + password[-2:]
    return "****"


def mask_field(kind, name, value):
    if kind == "card" and name == "number" and len(value) >= 4:
        return "*" * (len(value) - 4) + value[-4:]
    if value and name in KIND_SCHEMAS.get(kind, {}).get("sensitive", []):
        return mask_password(value)
    return value


def _suggest_service(connection, service):
    try:
        names = [r[0] for r in connection.execute("SELECT service FROM credentials").fetchall()]
    except sqlite3.Error:
        return None
    match = difflib.get_close_matches(service, names, n=1, cutoff=0.6)
    return match[0] if match else None


# ---------------------------------------------------------------------------
# Core operations
# ---------------------------------------------------------------------------

def read_secret(prompt, from_stdin=False):
    if from_stdin:
        try:
            value = sys.stdin.readline()
        except (OSError, ValueError) as exc:
            raise VaultError(f"cannot read secret from stdin: {exc}") from exc
        if value == "":
            raise VaultError("no secret received on stdin; use --password-stdin with piped input")
        value = value.rstrip("\r\n")
    elif sys.stdin.isatty():
        try:
            value = getpass.getpass(prompt)
        except (OSError, ValueError, KeyboardInterrupt) as exc:
            raise VaultError(f"cannot read secret: {exc}") from exc
    else:
        raise VaultError("no terminal available; use --password-stdin")
    if not value:
        raise VaultError("secret must not be empty")
    if len(value) > MAX_FIELD_VALUE_LEN:
        raise VaultError("secret too long")
    return value


def _store_record(service, kind, username, password, fields, meta):
    service = validate_service(service)
    kind = validate_kind(kind)
    username = validate_username(username)
    meta = validate_meta(meta)
    password = "" if password is None else str(password)
    if kind == "login" and len(password) > MAX_FIELD_VALUE_LEN:
        raise VaultError("password too long")
    fields = validate_fields(kind, fields or {})

    fernet = get_fernet()
    enc_password = fernet.encrypt(password.encode()).decode() if password else ""
    enc_fields = (
        fernet.encrypt(json.dumps(fields, ensure_ascii=False).encode()).decode()
        if fields
        else ""
    )
    now = _now_iso()
    with database() as connection:
        ensure_verifier(connection, fernet)
        try:
            existing = connection.execute(
                "SELECT id FROM credentials WHERE service = ?", (service,)
            ).fetchone()
            connection.execute(
                "INSERT INTO credentials (service, kind, username, encrypted_password, "
                "encrypted_fields, meta, updated_at, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(service) DO UPDATE SET "
                "kind=excluded.kind, username=excluded.username, "
                "encrypted_password=excluded.encrypted_password, "
                "encrypted_fields=excluded.encrypted_fields, "
                "meta=excluded.meta, updated_at=excluded.updated_at",
                (service, kind, username, enc_password, enc_fields, meta, now, now),
            )
        except sqlite3.Error as exc:
            raise VaultError(f"cannot store credential: {exc}") from exc
    print(f"{'Updated' if existing else 'Stored'}: {service} [{kind}]")
    return service


def set_credential(service, username, password, meta=""):
    """Legacy login store (kind='login'). Kept for backward compatibility."""
    return _store_record(service, "login", username, password or "", {}, meta or "")


def store_credential(service, kind="login", username="", password="", fields=None, meta=""):
    if kind == "login" and not password and fields and "password" in fields:
        password = fields.pop("password")
    if kind == "apikey" and not password and fields and "key" in fields:
        password = fields.pop("key")
    return _store_record(service, kind, username, password, fields, meta)


def _fetch_row(service):
    service = validate_service(service)
    with database() as connection:
        try:
            row = connection.execute(
                "SELECT service, kind, username, encrypted_password, "
                "encrypted_fields, meta FROM credentials WHERE service = ?",
                (service,),
            ).fetchone()
        except sqlite3.Error as exc:
            raise VaultError(f"cannot read vault: {exc}") from exc
        if not row:
            hint = _suggest_service(connection, service)
            msg = f"credential not found: {service}"
            if hint:
                msg += f" (did you mean '{hint}'?)"
            raise VaultError(msg)
        return row


def get_credential(service, show=False, json_output=False):
    service = validate_service(service)
    fernet = get_fernet()
    with database() as connection:
        validate_key(connection, fernet)
        try:
            row = connection.execute(
                "SELECT service, kind, username, encrypted_password, "
                "encrypted_fields, meta FROM credentials WHERE service = ?",
                (service,),
            ).fetchone()
        except sqlite3.Error as exc:
            raise VaultError(f"cannot read vault: {exc}") from exc
        if not row:
            hint = _suggest_service(connection, service)
            msg = f"credential not found: {service}"
            if hint:
                msg += f" (did you mean '{hint}'?)"
            raise VaultError(msg)
    name, kind, username, enc_password, enc_fields, meta = row
    password = _decrypt_text(fernet, enc_password, "password")
    fields = _decrypt_fields(fernet, enc_fields)

    if json_output:
        print(json.dumps(
            {
                "service": name,
                "kind": kind,
                "username": username,
                "password": password if show else None,
                "fields": fields if show else {
                    k: mask_field(kind, k, v) for k, v in fields.items()
                },
                "meta": meta,
            },
            ensure_ascii=False,
            indent=2,
        ))
        return

    print(f"Service: {name}")
    print(f"Type: {kind}")
    print(f"User: {username}")
    if kind in ("login", "apikey") or password:
        print(f"Pass: {password if show else (mask_password(password) if password else '(empty)')}")
    for key in sorted(fields):
        print(f"{key.capitalize()}: {fields[key] if show else mask_field(kind, key, fields[key])}")
    print(f"Meta: {meta}")


def list_credentials(json_output=False, warn_days=WARN_DAYS):
    try:
        warn_days = int(warn_days)
    except (TypeError, ValueError):
        raise VaultError("--warn-days must be an integer") from None
    if warn_days < 0:
        raise VaultError("--warn-days must be >= 0")
    fernet = get_fernet()
    with database() as connection:
        validate_key(connection, fernet)
        try:
            rows = connection.execute(
                "SELECT service, kind, username, updated_at FROM credentials ORDER BY service"
            ).fetchall()
        except sqlite3.Error as exc:
            raise VaultError(f"cannot list vault: {exc}") from exc
    if json_output:
        data = []
        for service, kind, username, updated_at in rows:
            entry = {
                "service": service,
                "kind": kind or "login",
                "username": username,
            }
            if updated_at:
                entry["updated_at"] = updated_at
                try:
                    dt = datetime.fromisoformat(updated_at)
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    age_days = (datetime.now(timezone.utc) - dt).days
                    entry["age_days"] = age_days
                    if age_days > warn_days:
                        entry["stale"] = True
                except (ValueError, TypeError):
                    pass
            data.append(entry)
        print(json.dumps(data if data else [], indent=2))
        return
    print("Vault Contents:")
    now = datetime.now(timezone.utc)
    for service, kind, username, updated_at in rows:
        line = f"- {service} [{kind or 'login'}] (User: {username})"
        if updated_at:
            try:
                dt = datetime.fromisoformat(updated_at)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                age = (now - dt).days
                line += f"  updated {age}d ago"
                if age > warn_days:
                    line += f"  [warn: >{warn_days}d, consider rotation]"
            except (ValueError, TypeError):
                pass
        print(line)


def delete_credential(service):
    service = validate_service(service)
    fernet = get_fernet()
    with database() as connection:
        validate_key(connection, fernet)
        try:
            cursor = connection.execute(
                "DELETE FROM credentials WHERE service = ?", (service,)
            )
        except sqlite3.Error as exc:
            raise VaultError(f"cannot delete credential: {exc}") from exc
        if not cursor.rowcount:
            hint = _suggest_service(connection, service)
            msg = f"credential not found: {service}"
            if hint:
                msg += f" (did you mean '{hint}'?)"
            raise VaultError(msg)
    print(f"Deleted: {service}")


def rotate_master_key(new_key):
    if isinstance(new_key, bytes):
        try:
            new_key = new_key.decode()
        except UnicodeDecodeError as exc:
            raise VaultError(f"invalid new master key: {exc}") from exc
    _check_key_strength(str(new_key), "MEMA_VAULT_NEW_MASTER_KEY")
    new_key = str(new_key)
    if not DB_PATH.is_file():
        raise VaultError(f"vault database not found: {DB_PATH} (nothing to rotate)")
    old_fernet = get_fernet()
    try:
        salt = SALT_PATH.read_bytes()
    except OSError as exc:
        raise VaultError(f"cannot read salt: {exc}") from exc
    new_fernet = derive_fernet(new_key.encode(), salt)
    with database() as connection:
        validate_key(connection, old_fernet)
        old_token = _get_verifier_token(connection)
    # Reject rotation to the same key (same key decrypts the verifier).
    if old_token:
        try:
            same = new_fernet.decrypt(old_token.encode()) == VERIFIER_PLAINTEXT
        except InvalidToken:
            same = False
        if same:
            raise VaultError("new master key must differ from the current one")
    backup_path = DB_PATH.with_name(
        f"{DB_PATH.name}.backup-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
    )
    try:
        shutil.copy2(DB_PATH, backup_path)
        backup_path.chmod(0o600)
    except OSError as exc:
        raise VaultError(f"cannot create backup: {exc}") from exc
    try:
        with database() as connection:
            rows = connection.execute(
                "SELECT id, encrypted_password, encrypted_fields FROM credentials"
            ).fetchall()
            # Trial-decrypt everything BEFORE writing (fail fast on wrong key).
            plaintext = [
                (
                    row_id,
                    old_fernet.decrypt(enc.encode()).decode() if enc else "",
                    old_fernet.decrypt(fld.encode()).decode() if fld else "",
                )
                for row_id, enc, fld in rows
            ]
            now = _now_iso()
            updates = [
                (
                    new_fernet.encrypt(p.encode()).decode() if p else "",
                    new_fernet.encrypt(f.encode()).decode() if f else "",
                    now,
                    row_id,
                )
                for row_id, p, f in plaintext
            ]
            connection.executemany(
                "UPDATE credentials SET encrypted_password = ?, "
                "encrypted_fields = ?, updated_at = ? WHERE id = ?",
                updates,
            )
            connection.execute(
                "INSERT INTO vault_meta (key, value) VALUES ('key_verifier', ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (new_fernet.encrypt(VERIFIER_PLAINTEXT).decode(),),
            )
    except InvalidToken:
        try:
            shutil.copy2(backup_path, DB_PATH)
            DB_PATH.chmod(0o600)
        except OSError:
            pass
        raise VaultError("invalid master key; rotation aborted, backup restored") from None
    except (sqlite3.Error, VaultError, OSError, ValueError) as exc:
        try:
            shutil.copy2(backup_path, DB_PATH)
            DB_PATH.chmod(0o600)
        except OSError:
            pass
        raise VaultError(f"rotation failed, backup restored: {exc}") from exc
    print(f"Rotated {len(rows)} credentials. Backup: {backup_path}")


def verify_vault():
    try:
        fernet = get_fernet()
    except VaultError as exc:
        raise VaultError(f"master key / salt problem: {exc}") from exc
    with database() as connection:
        try:
            validate_key(connection, fernet)
            kinds = connection.execute(
                "SELECT kind, count(*) FROM credentials GROUP BY kind"
            ).fetchall()
            count = sum(n for _, n in kinds)
        except (sqlite3.Error, VaultError) as exc:
            raise VaultError(f"verify failed: {exc}") from exc
    breakdown = ", ".join(f"{k or 'login'}:{n}" for k, n in kinds) if kinds else "empty"
    print(f"OK: master key valid, {count} credential(s) [{breakdown}], salt OK")
    return 0


def env_exec(service, env_var, command):
    if not command:
        raise VaultError("env: no command provided after --")
    if command and command[0] == "--env":
        if len(command) < 2:
            raise VaultError("env: --env requires an argument")
        env_var = command[1]
        command = command[2:]
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        raise VaultError("env: no command provided after --")
    row = _fetch_row(service)
    _name, kind, _u, enc_password, enc_fields, _m = row
    fernet = get_fernet()
    password = _decrypt_text(fernet, enc_password, "password")
    if not password and enc_fields:
        fields = _decrypt_fields(fernet, enc_fields)
        password = fields.get("key") or fields.get("password") or ""
    if not password:
        raise VaultError(f"credential '{service}' has no secret to inject")
    var_name = env_var
    if not var_name:
        var_name = service.upper().replace("-", "_").replace(" ", "_").replace("/", "_")
        var_name = "".join(c if c.isalnum() or c == "_" else "_" for c in var_name)
        if not var_name or var_name[0].isdigit():
            var_name = f"SVC_{var_name}"
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", var_name or ""):
        raise VaultError(f"invalid env var name: {var_name!r}")
    env = os.environ.copy()
    env[var_name] = password
    try:
        result = subprocess.run(command, env=env)
    except FileNotFoundError:
        raise VaultError(f"env: command not found: {command[0]}") from None
    except OSError as exc:
        raise VaultError(f"env: cannot run command: {exc}") from exc
    sys.exit(result.returncode)


def export_vault(out_path, fmt="enc"):
    if fmt != "enc":
        raise VaultError(f"unsupported export format: {fmt}")
    fernet = get_fernet()
    export_fernet = get_export_fernet()
    with database() as connection:
        validate_key(connection, fernet)
        try:
            rows = connection.execute(
                "SELECT service, kind, username, encrypted_password, "
                "encrypted_fields, meta, updated_at, created_at "
                "FROM credentials ORDER BY service"
            ).fetchall()
        except sqlite3.Error as exc:
            raise VaultError(f"cannot export vault: {exc}") from exc
    creds = []
    for service, kind, username, enc, enc_fields, meta, updated_at, created_at in rows:
        password = _decrypt_text(fernet, enc, f"password for '{service}'")
        fields = _decrypt_fields(fernet, enc_fields)
        creds.append(
            {
                "service": service,
                "kind": kind or "login",
                "username": username or "",
                "password": password,
                "fields": fields,
                "meta": meta or "",
                "updated_at": updated_at,
                "created_at": created_at,
            }
        )
    payload = json.dumps(
        {"version": EXPORT_VERSION, "exported_at": _now_iso(), "credentials": creds},
        ensure_ascii=False,
    ).encode()
    token = export_fernet.encrypt(payload)
    out_path = Path(out_path)
    try:
        out_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        out_path.write_bytes(token)
        out_path.chmod(0o600)
    except OSError as exc:
        raise VaultError(f"cannot write export file: {exc}") from exc
    print(f"Exported {len(creds)} credential(s) to {out_path} (encrypted, 0600)")


def import_vault(in_path, mode="merge"):
    if mode not in ("merge", "replace"):
        raise VaultError(f"invalid import mode: {mode}")
    in_path = Path(in_path)
    if not in_path.is_file():
        raise VaultError(f"import file not found: {in_path}")
    try:
        if in_path.stat().st_size > 10 * 1024 * 1024:
            raise VaultError("import file too large (>10MB)")
        token = in_path.read_bytes().strip()
    except OSError as exc:
        raise VaultError(f"cannot read import file: {exc}") from exc
    if not token:
        raise VaultError("import file is empty")
    export_fernet = get_export_fernet()
    local_fernet = get_fernet()
    try:
        payload = export_fernet.decrypt(token)
    except InvalidToken:
        raise VaultError("invalid master key for import file or corrupted file") from None
    try:
        data = json.loads(payload.decode())
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise VaultError(f"invalid import file format: {exc}") from exc
    creds = data.get("credentials", [])
    if not isinstance(creds, list):
        raise VaultError("invalid import file format")
    if len(creds) > 10_000:
        raise VaultError("import file contains too many credentials (>10000)")
    with database() as connection:
        ensure_verifier(connection, local_fernet)
        if mode == "replace":
            try:
                connection.execute("DELETE FROM credentials")
            except sqlite3.Error as exc:
                raise VaultError(f"cannot clear vault: {exc}") from exc
        count = 0
        skipped = 0
        for c in creds:
            if not isinstance(c, dict):
                skipped += 1
                continue
            try:
                service = validate_service(c.get("service", ""))
                kind = validate_kind(c.get("kind", "login"))
                username = validate_username(c.get("username", ""))
                meta = validate_meta(c.get("meta", ""))
                password = c.get("password") or ""
                fields = c.get("fields") or {}
                # v1 compat: password-only entries.
                if kind == "login" and fields and "password" in fields and not password:
                    password = fields.pop("password")
                fields = validate_fields(kind, fields)
            except VaultError as exc:
                print(f"Warning: skipping '{c.get('service', '?')}': {exc}", file=sys.stderr)
                skipped += 1
                continue
            updated_at = c.get("updated_at") or _now_iso()
            created_at = c.get("created_at") or updated_at
            enc = local_fernet.encrypt(str(password).encode()).decode() if password else ""
            enc_fields = (
                local_fernet.encrypt(
                    json.dumps(fields, ensure_ascii=False).encode()
                ).decode()
                if fields
                else ""
            )
            try:
                connection.execute(
                    "INSERT INTO credentials (service, kind, username, encrypted_password, "
                    "encrypted_fields, meta, updated_at, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(service) DO UPDATE SET "
                    "kind=excluded.kind, username=excluded.username, "
                    "encrypted_password=excluded.encrypted_password, "
                    "encrypted_fields=excluded.encrypted_fields, "
                    "meta=excluded.meta, updated_at=excluded.updated_at",
                    (service, kind, username, enc, enc_fields, meta, updated_at, created_at),
                )
            except sqlite3.Error as exc:
                print(f"Warning: skipping '{service}': {exc}", file=sys.stderr)
                skipped += 1
                continue
            count += 1
    msg = f"Imported {count} credential(s) from {in_path} (mode={mode})"
    if skipped:
        msg += f", skipped {skipped}"
    print(msg)


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser():
    parser = argparse.ArgumentParser(description="Mema Vault CLI (typed + hardened)")
    subparsers = parser.add_subparsers(dest="command", required=True)

    set_parser = subparsers.add_parser("set", help="store a login credential")
    set_parser.add_argument("service")
    set_parser.add_argument("username")
    set_parser.add_argument("--meta", default="")
    set_parser.add_argument("--password-stdin", action="store_true")

    store_parser = subparsers.add_parser(
        "store", help="store a typed record (card/address/note/apikey/generic/login)"
    )
    store_parser.add_argument("service")
    store_parser.add_argument("--kind", default="login", choices=list(KINDS))
    store_parser.add_argument("--username", default="")
    store_parser.add_argument("--meta", default="")
    store_parser.add_argument(
        "--field", action="append", default=[],
        help="extra field as KEY=VALUE (repeatable). For secrets prefer --secret-field.",
    )
    store_parser.add_argument(
        "--fields-json", default="",
        help="extra fields as a JSON object, e.g. '{\"city\": \"Bandung\"}'",
    )
    store_parser.add_argument(
        "--secret-field", action="append", default=[],
        help="field name whose value is read securely (prompt/stdin), e.g. --secret-field number",
    )
    store_parser.add_argument("--password-stdin", action="store_true",
                              help="read login password / apikey from stdin")
    store_parser.add_argument("--password", default=None,
                              help="login password (prefers stdin/prompt; flag kept for compat)")

    get_parser = subparsers.add_parser("get", help="retrieve a credential")
    get_parser.add_argument("service")
    get_parser.add_argument("--show", action="store_true", help="show raw secrets")
    get_parser.add_argument("--json", action="store_true", help="output as JSON")

    list_parser = subparsers.add_parser("list", help="list credentials")
    list_parser.add_argument("--json", action="store_true", help="output as JSON")
    list_parser.add_argument(
        "--warn-days", type=int, default=WARN_DAYS, help="stale threshold in days"
    )

    delete_parser = subparsers.add_parser("delete", help="delete a credential")
    delete_parser.add_argument("service")

    rotate_parser = subparsers.add_parser("rotate-key", help="rotate the master key")
    rotate_parser.add_argument("--new-key-stdin", action="store_true")

    subparsers.add_parser("verify", help="verify master key + salt")
    subparsers.add_parser("types", help="list supported record types")

    env_parser = subparsers.add_parser("env", help="run command with secret as env var")
    env_parser.add_argument("service", help="service name to inject")
    env_parser.add_argument(
        "--env",
        dest="env_var",
        default=None,
        help="env var name (default: SERVICE uppercased)",
    )
    env_parser.add_argument(
        "cmd", metavar="command", nargs=argparse.REMAINDER, help="command after --"
    )

    export_parser = subparsers.add_parser(
        "export", help="export vault to encrypted file"
    )
    export_parser.add_argument(
        "--out", required=True, type=Path, help="output file path"
    )
    export_parser.add_argument(
        "--format", choices=["enc"], default="enc", help="export format"
    )

    import_parser = subparsers.add_parser(
        "import", help="import vault from encrypted file"
    )
    import_parser.add_argument(
        "--in", dest="input", required=True, type=Path, help="input file path"
    )
    import_parser.add_argument(
        "--mode", choices=["merge", "replace"], default="merge", help="merge or replace"
    )

    return parser


def print_types():
    print("Supported types:")
    for kind in KINDS:
        schema = KIND_SCHEMAS[kind]
        req = ", ".join(schema["required"]) or "(none)"
        opt = ", ".join(schema["optional"]) or "(any)"
        print(f"- {kind}: {schema['help']}")
        print(f"    required: {req}; optional: {opt}")


def main():
    args = build_parser().parse_args()
    init_db()
    if args.command == "set":
        password = read_secret("Password: ", args.password_stdin)
        set_credential(args.service, args.username, password, args.meta)
    elif args.command == "store":
        fields = parse_field_args(args.field, args.fields_json)
        password = ""
        if args.kind in ("login", "apikey"):
            if args.password is not None:
                print("Warning: --password exposes the secret in process args; "
                      "prefer --password-stdin.", file=sys.stderr)
                password = args.password
                if not password:
                    raise VaultError("secret must not be empty")
            elif args.password_stdin:
                password = read_secret("Password: ", True)
            elif sys.stdin.isatty():
                password = read_secret("Password: ", False)
            # apikey alias: --field key=... works as the secret too
            if args.kind == "apikey" and not password and "key" in fields:
                password = fields.pop("key")
        for name in args.secret_field:
            name = name.strip()
            if not name:
                raise VaultError("empty --secret-field name")
            if name in fields:
                raise VaultError(f"--secret-field '{name}' also passed via --field")
            fields[name] = read_secret(
                f"{name}: ",
                from_stdin=not sys.stdin.isatty() or args.password_stdin,
            )
        store_credential(
            args.service, kind=args.kind, username=args.username,
            password=password, fields=fields, meta=args.meta,
        )
    elif args.command == "get":
        get_credential(args.service, args.show, json_output=args.json)
    elif args.command == "list":
        list_credentials(json_output=args.json, warn_days=args.warn_days)
    elif args.command == "delete":
        delete_credential(args.service)
    elif args.command == "rotate-key":
        new_key = os.environ.get("MEMA_VAULT_NEW_MASTER_KEY")
        if not new_key:
            new_key = read_secret("New master key: ", args.new_key_stdin)
        if not args.new_key_stdin and "MEMA_VAULT_NEW_MASTER_KEY" not in os.environ:
            try:
                confirmation = getpass.getpass("Confirm new master key: ")
            except (OSError, ValueError, KeyboardInterrupt) as exc:
                raise VaultError(f"cannot read confirmation: {exc}") from exc
            if new_key != confirmation:
                raise VaultError("new master keys do not match")
        rotate_master_key(new_key)
    elif args.command == "verify":
        verify_vault()
    elif args.command == "types":
        print_types()
    elif args.command == "env":
        env_exec(args.service, args.env_var, args.cmd)
    elif args.command == "export":
        export_vault(args.out, args.format)
    elif args.command == "import":
        import_vault(args.input, args.mode)


if __name__ == "__main__":
    try:
        main()
    except BrokenPipeError:
        try:
            sys.stdout.close()
        except Exception:
            pass
        sys.exit(0)
    except KeyboardInterrupt:
        print("\nAborted.", file=sys.stderr)
        sys.exit(130)
    except InvalidToken:
        print("Error: invalid master key or corrupted credential", file=sys.stderr)
        sys.exit(2)
    except (OSError, sqlite3.Error, VaultError) as error:
        print(f"Error: {error}", file=sys.stderr)
        sys.exit(1)
