"""Encrypted password vault: file format, entry store, lifecycle.

File layout (all integers big-endian)::

    offset  size  field
    0       8     magic b"PASSVLT1"
    8       4     PBKDF2 iterations (uint32)
    12      16    salt
    28      16    nonce
    44      4     ciphertext length (uint32)
    48      n     ciphertext (AES-style stream XOR of the JSON payload)
    48+n    32    HMAC-SHA256 tag over header || ciphertext

The JSON payload (UTF-8, sorted keys, compact separators) is::

    {"entries": {"<name>": {"notes": ..., "password": ...,
                            "updated": ..., "username": ...}},
     "format": "passvault/1"}

The encryption key comes from PBKDF2-HMAC-SHA256 using the stored salt and
iteration count; the MAC key is derived header-independently (see
:mod:`passvault.crypto`) so the tag can be checked *before* the
untrusted iteration count is honoured.  The tag covers the header *and*
ciphertext, so loading fails closed with :class:`AuthenticationError` on
a wrong password or on any modified byte.
"""
from __future__ import annotations

import json
import os
import secrets
import struct
import time
from pathlib import Path
from typing import Callable, Iterable

from . import crypto

__all__ = [
    "MAGIC",
    "VERSION",
    "DEFAULT_ITERATIONS",
    "MAX_ITERATIONS",
    "HEADER_LEN",
    "TAG_LEN",
    "VaultError",
    "FormatError",
    "AuthenticationError",
    "EntryNotFoundError",
    "DuplicateEntryError",
    "Vault",
]

MAGIC = b"PASSVLT1"
VERSION = "passvault/1"
DEFAULT_ITERATIONS = 200_000
MAX_ITERATIONS = 10_000_000  # header sanity bound: rejects runaway KDF costs
HEADER_LEN = 48
TAG_LEN = 32
_HEADER_STRUCT = struct.Struct(">8sI16s16sI")


class VaultError(Exception):
    """Base class for every vault failure."""


class FormatError(VaultError):
    """The blob is not a vault: bad magic, truncated, impossible length."""


class AuthenticationError(VaultError):
    """Wrong master password or tampered vault contents."""


class EntryNotFoundError(VaultError):
    """No entry with the requested name."""


class DuplicateEntryError(VaultError):
    """An entry with that name already exists and overwrite was not set."""


def _pack_payload(entries: dict[str, dict]) -> bytes:
    payload = {"format": VERSION, "entries": entries}
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _unpack_payload(raw: bytes) -> dict[str, dict]:
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AuthenticationError("decrypted payload is not valid JSON") from exc
    if not isinstance(doc, dict) or doc.get("format") != VERSION:
        raise AuthenticationError("decrypted payload has an unknown format")
    entries = doc.get("entries")
    if not isinstance(entries, dict):
        raise AuthenticationError("decrypted payload has no entry table")
    for name, entry in entries.items():
        if not isinstance(name, str) or not isinstance(entry, dict):
            raise AuthenticationError("decrypted payload contains a malformed entry")
    return entries


class Vault:
    """An unlocked in-memory vault bound to one master password.

    Use :meth:`create` to start empty and :meth:`load_bytes` /
    :meth:`load` to open an existing one.  ``salt`` and ``nonce`` are
    injectable so tests (and the CLI's ``--salt-hex`` debug flag) can be
    fully deterministic; production callers leave them unset and get
    16 fresh ``secrets.token_bytes`` values.
    """

    def __init__(
        self,
        entries: dict[str, dict],
        *,
        password: bytes,
        salt: bytes,
        nonce: bytes,
        iterations: int,
        clock: Callable[[], float],
    ) -> None:
        self._entries = entries
        self._password = password
        self._salt = salt
        self._nonce = nonce
        self._iterations = iterations
        self._clock = clock

    # ------------------------------------------------------------- creation

    @classmethod
    def create(
        cls,
        password: bytes | str,
        *,
        iterations: int = DEFAULT_ITERATIONS,
        salt: bytes | None = None,
        nonce: bytes | None = None,
        clock: Callable[[], float] = time.time,
    ) -> "Vault":
        """Create an empty, unlocked vault."""
        pw = password.encode("utf-8") if isinstance(password, str) else password
        if not pw:
            raise VaultError("master password must not be empty")
        return cls(
            {},
            password=pw,
            salt=salt if salt is not None else secrets.token_bytes(crypto.SALT_LEN),
            nonce=nonce if nonce is not None else secrets.token_bytes(crypto.NONCE_LEN),
            iterations=iterations,
            clock=clock,
        )

    @classmethod
    def load_bytes(
        cls,
        blob: bytes,
        password: bytes | str,
        *,
        clock: Callable[[], float] = time.time,
    ) -> "Vault":
        """Decode, authenticate and decrypt a vault blob."""
        pw = password.encode("utf-8") if isinstance(password, str) else password
        if len(blob) < HEADER_LEN + TAG_LEN:
            raise FormatError(f"vault blob too short: {len(blob)} bytes")
        magic, iterations, salt, nonce, ct_len = _HEADER_STRUCT.unpack_from(blob, 0)
        if magic != MAGIC:
            raise FormatError("not a passvault file (bad magic)")
        if ct_len != len(blob) - HEADER_LEN - TAG_LEN:
            raise FormatError(
                f"ciphertext length {ct_len} does not match file size {len(blob)}"
            )
        ciphertext = blob[HEADER_LEN : HEADER_LEN + ct_len]
        tag = blob[HEADER_LEN + ct_len :]
        header = blob[:HEADER_LEN]
        # Authenticate first with the header-independent MAC key: a tampered
        # iteration count must be rejected before it can cost any PBKDF2 work,
        # and must be reported as tampering rather than as a format quirk.
        mac_key = crypto.derive_mac_key(pw, salt)
        if not crypto.verify_mac(mac_key, tag, header, ciphertext):
            raise AuthenticationError("wrong master password or tampered vault")
        # Header is authentic now, so its KDF parameters are trusted.
        if iterations < 1:
            raise FormatError("invalid PBKDF2 iteration count in header")
        if iterations > MAX_ITERATIONS:
            raise FormatError(
                f"PBKDF2 iteration count {iterations} exceeds limit {MAX_ITERATIONS}"
            )
        enc_key = crypto.derive_enc_key(pw, salt, iterations)
        plaintext = crypto.keystream_xor(enc_key, nonce, ciphertext)
        entries = _unpack_payload(plaintext)
        return cls(
            entries,
            password=pw,
            salt=salt,
            nonce=nonce,
            iterations=iterations,
            clock=clock,
        )

    @classmethod
    def load(
        cls,
        path: str | Path,
        password: bytes | str,
        *,
        clock: Callable[[], float] = time.time,
    ) -> "Vault":
        """Read and open a vault file."""
        try:
            blob = Path(path).read_bytes()
        except OSError as exc:
            raise VaultError(f"cannot read vault file {path}: {exc}") from exc
        return cls.load_bytes(blob, password, clock=clock)

    # ------------------------------------------------------------ persistence

    def save_bytes(self) -> bytes:
        """Serialize and encrypt the vault into a portable blob."""
        enc_key = crypto.derive_enc_key(self._password, self._salt, self._iterations)
        mac_key = crypto.derive_mac_key(self._password, self._salt)
        ciphertext = crypto.keystream_xor(enc_key, self._nonce, _pack_payload(self._entries))
        header = _HEADER_STRUCT.pack(
            MAGIC, self._iterations, self._salt, self._nonce, len(ciphertext)
        )
        return header + ciphertext + crypto.mac(mac_key, header, ciphertext)

    def save(self, path: str | Path) -> None:
        """Atomically write the vault (temp file + ``os.replace``)."""
        target = Path(path)
        tmp = target.with_name(target.name + ".tmp")
        tmp.write_bytes(self.save_bytes())
        os.replace(tmp, target)

    # ---------------------------------------------------------------- entries

    @staticmethod
    def _check_name(name: str) -> str:
        if not isinstance(name, str) or not name.strip():
            raise VaultError("entry name must be a non-empty string")
        return name

    def add(
        self,
        name: str,
        value: str,
        *,
        username: str = "",
        notes: str = "",
        overwrite: bool = False,
    ) -> None:
        """Store a secret under ``name`` (fails if it exists)."""
        name = self._check_name(name)
        if name in self._entries and not overwrite:
            raise DuplicateEntryError(f"entry {name!r} already exists")
        self._entries[name] = {
            "password": value,
            "username": username,
            "notes": notes,
            "updated": self._clock(),
        }

    def get(self, name: str) -> dict:
        """Return a copy of the entry ``name``."""
        name = self._check_name(name)
        if name not in self._entries:
            raise EntryNotFoundError(f"no entry named {name!r}")
        return dict(self._entries[name])

    def delete(self, name: str) -> None:
        """Remove entry ``name``; :class:`EntryNotFoundError` if absent."""
        name = self._check_name(name)
        if name not in self._entries:
            raise EntryNotFoundError(f"no entry named {name!r}")
        del self._entries[name]

    def list_names(self) -> list[str]:
        """All entry names in sorted order."""
        return sorted(self._entries)

    def search(self, substring: str) -> list[str]:
        """Sorted names containing ``substring`` (case-insensitive)."""
        needle = substring.lower()
        return sorted(n for n in self._entries if needle in n.lower())

    @property
    def entries(self) -> dict[str, dict]:
        """A deep-ish copy of the whole entry table."""
        return {name: dict(entry) for name, entry in self._entries.items()}

    def __len__(self) -> int:
        return len(self._entries)

    # ------------------------------------------------------------ re-keying

    def change_password(
        self,
        new_password: bytes | str,
        *,
        iterations: int | None = None,
        salt: bytes | None = None,
        nonce: bytes | None = None,
    ) -> None:
        """Re-encrypt the vault under a new master password.

        A fresh salt and nonce are generated unless injected, so the same
        plaintext never produces the same ciphertext twice.
        """
        pw = new_password.encode("utf-8") if isinstance(new_password, str) else new_password
        if not pw:
            raise VaultError("master password must not be empty")
        self._password = pw
        self._iterations = iterations if iterations is not None else self._iterations
        self._salt = salt if salt is not None else secrets.token_bytes(crypto.SALT_LEN)
        self._nonce = nonce if nonce is not None else secrets.token_bytes(crypto.NONCE_LEN)

    def names_matching(self, names: Iterable[str]) -> list[str]:
        """Helper: filter ``names`` down to those present in the vault."""
        return sorted(n for n in names if n in self._entries)
