"""Tests for the passvault encrypted password vault.

Security posture exercised here: wrong passwords and every kind of
tampering must fail with a *specific* exception and never return
plaintext; encryption with injected salt/nonce must be deterministic so
byte-level expectations are stable.
"""
from __future__ import annotations

import contextlib
import io
import os
import tempfile
import unittest
from pathlib import Path

from passvault import (
    DEFAULT_ITERATIONS,
    HEADER_LEN,
    MAGIC,
    MAX_ITERATIONS,
    TAG_LEN,
    AuthenticationError,
    DuplicateEntryError,
    EntryNotFoundError,
    FormatError,
    Vault,
    VaultError,
    derive_enc_key,
    derive_mac_key,
    keystream_xor,
)
from passvault.cli import main

SALT = bytes(range(16))
NONCE = bytes(range(16, 32))
ITER = 1000
MASTER = "correct horse battery staple"


def make_vault(clock=lambda: 1_700_000_000.0, password=MASTER) -> Vault:
    return Vault.create(
        password, iterations=ITER, salt=SALT, nonce=NONCE, clock=clock
    )


class CryptoTests(unittest.TestCase):
    def test_keystream_is_involution(self) -> None:
        key = derive_enc_key(b"pw", SALT, 100)
        data = bytes(range(256)) * 3
        encrypted = keystream_xor(key, NONCE, data)
        self.assertNotEqual(encrypted, data)
        self.assertEqual(keystream_xor(key, NONCE, encrypted), data)

    def test_keystream_differs_per_nonce(self) -> None:
        key = derive_enc_key(b"pw", SALT, 100)
        data = b"attack at dawn" * 10
        self.assertNotEqual(
            keystream_xor(key, NONCE, data),
            keystream_xor(key, bytes(16), data),
        )

    def test_derive_enc_key_rejects_bad_params(self) -> None:
        with self.assertRaises(ValueError):
            derive_enc_key(b"pw", SALT, 0)
        with self.assertRaises(ValueError):
            derive_enc_key(b"pw", b"", 100)
        with self.assertRaises(ValueError):
            derive_mac_key(b"pw", b"")

    def test_derivation_is_deterministic_and_keyed(self) -> None:
        self.assertEqual(
            derive_enc_key(b"pw", SALT, 100), derive_enc_key(b"pw", SALT, 100)
        )
        self.assertNotEqual(
            derive_enc_key(b"pw", SALT, 100), derive_enc_key(b"pw", SALT, 101)
        )
        self.assertNotEqual(
            derive_enc_key(b"pw", SALT, 100), derive_enc_key(b"pw2", SALT, 100)
        )
        mac_a = derive_mac_key(b"pw", SALT)
        self.assertEqual(mac_a, derive_mac_key(b"pw", SALT))
        self.assertNotEqual(mac_a, derive_mac_key(b"pw", bytes(16)))
        self.assertNotEqual(mac_a, derive_enc_key(b"pw", SALT, 100))

    def test_mac_key_is_header_independent(self) -> None:
        # The MAC key must not depend on the iteration count: that is what
        # lets tamper detection run before the untrusted header is honoured.
        self.assertEqual(
            derive_mac_key(b"pw", SALT), derive_mac_key(b"pw", SALT)
        )
        self.assertEqual(len(derive_mac_key(b"pw", SALT)), 32)


class VaultRoundtripTests(unittest.TestCase):
    def test_add_get_list_delete_roundtrip(self) -> None:
        vault = make_vault()
        vault.add("github", "hunter2", username="alice")
        vault.add("email", "pa55word", notes="work account")
        self.assertEqual(vault.list_names(), ["email", "github"])
        self.assertEqual(vault.get("github")["password"], "hunter2")
        self.assertEqual(vault.get("github")["username"], "alice")
        self.assertEqual(vault.get("email")["notes"], "work account")
        vault.delete("email")
        self.assertEqual(vault.list_names(), ["github"])
        self.assertEqual(len(vault), 1)

    def test_save_load_roundtrip_preserves_unicode(self) -> None:
        vault = make_vault()
        vault.add("notes", "pässwörd 🔐", username="üser")
        blob = vault.save_bytes()
        opened = Vault.load_bytes(blob, MASTER)
        entry = opened.get("notes")
        self.assertEqual(entry["password"], "pässwörd 🔐")
        self.assertEqual(entry["username"], "üser")
        self.assertEqual(opened.list_names(), ["notes"])

    def test_empty_vault_roundtrip(self) -> None:
        blob = make_vault().save_bytes()
        opened = Vault.load_bytes(blob, MASTER)
        self.assertEqual(len(opened), 0)
        self.assertEqual(opened.list_names(), [])

    def test_get_returns_copy_not_reference(self) -> None:
        vault = make_vault()
        vault.add("a", "secret")
        entry = vault.get("a")
        entry["password"] = "tampered"
        self.assertEqual(vault.get("a")["password"], "secret")

    def test_search_is_case_insensitive(self) -> None:
        vault = make_vault()
        vault.add("GitHub", "x")
        vault.add("gitlab", "y")
        vault.add("email", "z")
        self.assertEqual(vault.search("git"), ["GitHub", "gitlab"])
        self.assertEqual(vault.search("GIT"), ["GitHub", "gitlab"])
        self.assertEqual(vault.search("nope"), [])


class VaultFailureTests(unittest.TestCase):
    def test_wrong_password_raises_authentication_error(self) -> None:
        blob = make_vault().save_bytes()
        with self.assertRaises(AuthenticationError):
            Vault.load_bytes(blob, "wrong password")

    def test_tampered_ciphertext_detected(self) -> None:
        blob = bytearray(make_vault().save_bytes())
        blob[HEADER_LEN] ^= 0x01  # flip one ciphertext bit
        with self.assertRaises(AuthenticationError):
            Vault.load_bytes(bytes(blob), MASTER)

    def test_tampered_tag_detected(self) -> None:
        blob = bytearray(make_vault().save_bytes())
        blob[-1] ^= 0x80
        with self.assertRaises(AuthenticationError):
            Vault.load_bytes(bytes(blob), MASTER)

    def test_tampered_header_iteration_count_detected(self) -> None:
        blob = bytearray(make_vault().save_bytes())
        blob[8] ^= 0x01  # PBKDF2 iterations are inside the MAC'd header
        # Must fail as tampering (not with a KDF/format error) and must not
        # honour the forged 16.7M iteration count: the MAC check runs first.
        with self.assertRaises(AuthenticationError):
            Vault.load_bytes(bytes(blob), MASTER)

    def test_runaway_iteration_count_rejected_even_if_mac_matches(self) -> None:
        # A structurally valid header with an absurd iteration count is a
        # format error, never a multi-minute PBKDF2 stall.
        vault = make_vault()
        blob = bytearray(vault.save_bytes())
        blob[8:12] = (MAX_ITERATIONS + 1).to_bytes(4, "big")
        # Re-tag with a correct MAC so only the iteration bound is tested.
        import struct as _struct

        _, iterations, salt, nonce, ct_len = _struct.unpack_from(">8sI16s16sI", blob, 0)
        self.assertEqual(iterations, MAX_ITERATIONS + 1)
        from passvault import crypto, mac as _mac_fn

        mac_key = crypto.derive_mac_key(MASTER.encode(), salt)
        tag = _mac_fn(
            mac_key, bytes(blob[:HEADER_LEN]), bytes(blob[HEADER_LEN : HEADER_LEN + ct_len])
        )
        blob[-TAG_LEN:] = tag
        with self.assertRaises(FormatError):
            Vault.load_bytes(bytes(blob), MASTER)

    def test_bad_magic_raises_format_error(self) -> None:
        blob = bytearray(make_vault().save_bytes())
        blob[0:4] = b"NOPE"
        with self.assertRaises(FormatError):
            Vault.load_bytes(bytes(blob), MASTER)

    def test_truncated_blob_raises_format_error(self) -> None:
        with self.assertRaises(FormatError):
            Vault.load_bytes(b"short", MASTER)
        blob = make_vault().save_bytes()
        with self.assertRaises(FormatError):
            Vault.load_bytes(blob[: HEADER_LEN + TAG_LEN - 1], MASTER)

    def test_declared_length_mismatch_raises_format_error(self) -> None:
        blob = bytearray(make_vault().save_bytes())
        blob[44:48] = (12345).to_bytes(4, "big")
        with self.assertRaises(FormatError):
            Vault.load_bytes(bytes(blob), MASTER)

    def test_missing_entry_raises_entry_not_found(self) -> None:
        vault = make_vault()
        vault.add("a", "x")
        with self.assertRaises(EntryNotFoundError):
            vault.get("missing")
        with self.assertRaises(EntryNotFoundError):
            vault.delete("missing")

    def test_duplicate_add_rejected_unless_overwrite(self) -> None:
        vault = make_vault()
        vault.add("a", "first")
        with self.assertRaises(DuplicateEntryError):
            vault.add("a", "second")
        vault.add("a", "second", overwrite=True)
        self.assertEqual(vault.get("a")["password"], "second")

    def test_empty_name_rejected(self) -> None:
        vault = make_vault()
        with self.assertRaises(VaultError):
            vault.add("", "x")
        with self.assertRaises(VaultError):
            vault.add("   ", "x")


class VaultPropertyTests(unittest.TestCase):
    def test_deterministic_bytes_with_injected_salt_and_nonce(self) -> None:
        first = make_vault().save_bytes()
        second = make_vault().save_bytes()
        self.assertEqual(first, second)

    def test_ciphertext_does_not_leak_plaintext(self) -> None:
        vault = make_vault()
        vault.add("github", "super-secret-value", username="alice")
        blob = vault.save_bytes()
        self.assertNotIn(b"super-secret-value", blob)
        self.assertNotIn(b"github", blob)
        self.assertNotIn(b"alice", blob)

    def test_blob_layout_matches_documented_format(self) -> None:
        # Empty payload is the known compact JSON `{"entries":{},"format":...}`.
        empty_payload = b'{"entries":{},"format":"passvault/1"}'
        blob = make_vault().save_bytes()
        self.assertTrue(blob.startswith(MAGIC))
        self.assertEqual(len(blob[:HEADER_LEN]), HEADER_LEN)
        self.assertEqual(len(blob[-TAG_LEN:]), TAG_LEN)
        self.assertEqual(len(blob[HEADER_LEN:-TAG_LEN]), len(empty_payload))
        # Bigger plaintext must produce a proportionally bigger ciphertext.
        big = make_vault()
        big.add("a", "x" * 100)
        self.assertGreater(len(big.save_bytes()), len(blob))

    def test_change_password_rekeys_and_preserves_entries(self) -> None:
        vault = make_vault()
        vault.add("github", "hunter2", username="alice")
        old_blob = vault.save_bytes()
        vault.change_password("new master", salt=bytes(16), nonce=bytes(range(16, 32)))
        new_blob = vault.save_bytes()
        self.assertNotEqual(old_blob, new_blob)
        with self.assertRaises(AuthenticationError):
            Vault.load_bytes(new_blob, MASTER)
        with self.assertRaises(AuthenticationError):
            Vault.load_bytes(old_blob, "new master")
        opened = Vault.load_bytes(new_blob, "new master")
        self.assertEqual(opened.get("github")["password"], "hunter2")
        self.assertEqual(opened.get("github")["username"], "alice")

    def test_timestamps_come_from_injected_clock(self) -> None:
        vault = make_vault(clock=lambda: 42.5)
        vault.add("a", "x")
        self.assertEqual(vault.get("a")["updated"], 42.5)

    def test_save_and_load_via_file_is_atomic_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "demo.pvault"
            vault = make_vault()
            vault.add("a", "secret-value")
            vault.save(path)
            self.assertTrue(path.exists())
            self.assertFalse((Path(tmp) / "demo.pvault.tmp").exists())
            opened = Vault.load(path, MASTER)
            self.assertEqual(opened.get("a")["password"], "secret-value")
            with self.assertRaises(VaultError):
                Vault.load(path, "nope")


class CliTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.path = str(Path(self._tmp.name) / "cli.pvault")
        self._saved = {
            k: os.environ.get(k)
            for k in ("PASSVAULT_MASTER", "PASSVAULT_NEW", "PASSVAULT_VALUE")
        }
        os.environ["PASSVAULT_MASTER"] = MASTER

    def tearDown(self) -> None:
        for key, value in self._saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        self._tmp.cleanup()

    def cli(self, argv: list[str]) -> int:
        """Run the CLI with stdout/stderr captured (quiet test output)."""
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(
            io.StringIO()
        ):
            return main(argv)

    def test_cli_init_add_list_get_remove(self) -> None:
        self.assertEqual(self.cli(["init", "--path", self.path, "--iterations", "500"]), 0)
        rc = self.cli(
            [
                "add",
                "--path",
                self.path,
                "--name",
                "github",
                "--value",
                "hunter2",
                "--username",
                "alice",
            ]
        )
        self.assertEqual(rc, 0)
        self.assertEqual(self.cli(["list", "--path", self.path]), 0)
        self.assertEqual(self.cli(["get", "--path", self.path, "--name", "github"]), 0)
        self.assertEqual(self.cli(["remove", "--path", self.path, "--name", "github"]), 0)
        self.assertEqual(self.cli(["list", "--path", self.path]), 0)

    def test_cli_wrong_password_fails_cleanly(self) -> None:
        self.assertEqual(self.cli(["init", "--path", self.path, "--iterations", "500"]), 0)
        os.environ["PASSVAULT_MASTER"] = "wrong"
        self.assertEqual(self.cli(["list", "--path", self.path]), 1)

    def test_cli_duplicate_add_without_overwrite_fails(self) -> None:
        self.cli(["init", "--path", self.path, "--iterations", "500"])
        self.cli(["add", "--path", self.path, "--name", "a", "--value", "1"])
        rc = self.cli(["add", "--path", self.path, "--name", "a", "--value", "2"])
        self.assertEqual(rc, 1)

    def test_cli_passwd_changes_key(self) -> None:
        self.cli(["init", "--path", self.path, "--iterations", "500"])
        self.cli(["add", "--path", self.path, "--name", "a", "--value", "v"])
        os.environ["PASSVAULT_NEW"] = "brand new"
        self.assertEqual(self.cli(["passwd", "--path", self.path]), 0)
        self.assertEqual(self.cli(["list", "--path", self.path]), 1)  # old key dead
        os.environ["PASSVAULT_MASTER"] = "brand new"
        self.assertEqual(self.cli(["list", "--path", self.path]), 0)

    def test_cli_get_missing_entry_fails(self) -> None:
        self.cli(["init", "--path", self.path, "--iterations", "500"])
        self.assertEqual(self.cli(["get", "--path", self.path, "--name", "ghost"]), 1)

    def test_default_iterations_constant_is_production_grade(self) -> None:
        self.assertGreaterEqual(DEFAULT_ITERATIONS, 100_000)


if __name__ == "__main__":
    unittest.main()
