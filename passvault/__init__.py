"""passvault -- an encrypted password vault with a tiny auditable format.

Public API::

    from passvault import Vault, AuthenticationError

    vault = Vault.create("correct horse battery staple")
    vault.add("github", "s3cret", username="alice")
    blob = vault.save_bytes()

    opened = Vault.load_bytes(blob, "correct horse battery staple")
    opened.get("github")["password"]  # -> "s3cret"
"""
from .crypto import derive_enc_key, derive_mac_key, keystream_xor, mac, verify_mac
from .vault import (
    DEFAULT_ITERATIONS,
    HEADER_LEN,
    MAGIC,
    MAX_ITERATIONS,
    TAG_LEN,
    VERSION,
    AuthenticationError,
    DuplicateEntryError,
    EntryNotFoundError,
    FormatError,
    Vault,
    VaultError,
)

__all__ = [
    "Vault",
    "VaultError",
    "FormatError",
    "AuthenticationError",
    "EntryNotFoundError",
    "DuplicateEntryError",
    "MAGIC",
    "VERSION",
    "DEFAULT_ITERATIONS",
    "MAX_ITERATIONS",
    "HEADER_LEN",
    "TAG_LEN",
    "derive_enc_key",
    "derive_mac_key",
    "keystream_xor",
    "mac",
    "verify_mac",
]
