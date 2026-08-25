import contextlib
import importlib.util
import io
import os
import sqlite3
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from cryptography.fernet import InvalidToken

import sys

VAULT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "vault.py"
SPEC = importlib.util.spec_from_file_location("vault", VAULT_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load {VAULT_PATH}")
vault = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(vault)

PACKAGE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "package_skill.py"
PACKAGE_SPEC = importlib.util.spec_from_file_location("package_skill", PACKAGE_PATH)
if PACKAGE_SPEC is None or PACKAGE_SPEC.loader is None:
    raise RuntimeError(f"cannot load {PACKAGE_PATH}")
package_skill = importlib.util.module_from_spec(PACKAGE_SPEC)
PACKAGE_SPEC.loader.exec_module(package_skill)


class VaultTestCase(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        root = Path(self.temp_dir.name)
        self.db_path = root / "vault.db"
        self.salt_path = root / "salt.bin"
        self.path_patch = mock.patch.multiple(
            vault, DB_PATH=self.db_path, SALT_PATH=self.salt_path
        )
        self.path_patch.start()
        self.addCleanup(self.path_patch.stop)
        self.env_patch = mock.patch.dict(
            os.environ,
            {"MEMA_VAULT_MASTER_KEY": "legacy-master-key"},
            clear=True,
        )
        self.env_patch.start()
        self.addCleanup(self.env_patch.stop)
        vault.init_db()

    def test_reads_legacy_ciphertext_and_masks_secret(self):
        legacy_ciphertext = vault.get_fernet().encrypt(b"legacy-secret").decode()
        with contextlib.closing(sqlite3.connect(self.db_path)) as connection:
            connection.execute(
                "INSERT INTO credentials "
                "(service, username, encrypted_password, meta) VALUES (?, ?, ?, ?)",
                ("legacy", "user", legacy_ciphertext, "note"),
            )
            connection.commit()

        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            vault.get_credential("legacy")

        self.assertIn("Pass: le*********et", output.getvalue())
        self.assertNotIn("legacy-secret", output.getvalue())

    def test_set_updates_exact_service_only(self):
        vault.set_credential("api", "first", "one")
        vault.set_credential("api-prod", "second", "two")
        vault.set_credential("api", "updated", "three")

        with contextlib.closing(sqlite3.connect(self.db_path)) as connection:
            rows = connection.execute(
                "SELECT service, username FROM credentials ORDER BY service"
            ).fetchall()
        self.assertEqual(rows, [("api", "updated"), ("api-prod", "second")])

    def test_wrong_key_fails_authenticated_list(self):
        vault.set_credential("service", "user", "secret")
        os.environ["MEMA_VAULT_MASTER_KEY"] = "wrong-key"

        with self.assertRaises(InvalidToken):
            vault.list_credentials()

    def test_rotation_preserves_every_secret_and_creates_backup(self):
        vault.set_credential("one", "user", "secret-one")
        vault.set_credential("two", "user", "secret-two")
        old_fernet = vault.get_fernet()

        vault.rotate_master_key("new-master-key")

        backups = list(self.db_path.parent.glob("vault.db.backup-*"))
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].stat().st_mode & 0o777, 0o600)
        os.environ["MEMA_VAULT_MASTER_KEY"] = "new-master-key"
        new_fernet = vault.get_fernet()
        with contextlib.closing(sqlite3.connect(self.db_path)) as connection:
            tokens = [
                row[0]
                for row in connection.execute(
                    "SELECT encrypted_password FROM credentials ORDER BY service"
                )
            ]
        self.assertEqual(
            [new_fernet.decrypt(token.encode()) for token in tokens],
            [b"secret-one", b"secret-two"],
        )
        with self.assertRaises(InvalidToken):
            old_fernet.decrypt(tokens[0].encode())

    def test_runtime_files_are_owner_only(self):
        vault.set_credential("service", "user", "secret")
        self.assertEqual(self.db_path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.salt_path.stat().st_mode & 0o777, 0o600)

    def test_noninteractive_secret_requires_stdin_flag(self):
        with mock.patch.object(sys.stdin, "isatty", return_value=False):
            with self.assertRaisesRegex(vault.VaultError, "--password-stdin"):
                vault.read_secret("Password: ")

    def test_terminal_user_can_enter_master_key(self):
        os.environ.pop("MEMA_VAULT_MASTER_KEY")
        with mock.patch.object(sys.stdin, "isatty", return_value=True):
            with mock.patch.object(vault.getpass, "getpass", return_value="user-key"):
                self.assertEqual(vault.get_master_key(), b"user-key")

    def test_legacy_master_key_environment_is_supported(self):
        os.environ.pop("MEMA_VAULT_MASTER_KEY")
        os.environ["MASTER_KEY"] = "legacy-key"
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(vault.get_master_key(), b"legacy-key")


class PackageTestCase(unittest.TestCase):
    def test_package_excludes_runtime_secrets(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "mema-vault.skill"
            package_skill.package(output)
            with zipfile.ZipFile(output) as archive:
                names = set(archive.namelist())
        self.assertIn("mema-vault/scripts/vault.py", names)
        self.assertIn("mema-vault/README.md", names)
        self.assertNotIn("mema-vault/.env", names)
        self.assertNotIn("mema-vault/data/vault.db", names)
        self.assertNotIn("mema-vault/data/salt.bin", names)


if __name__ == "__main__":
    unittest.main()
