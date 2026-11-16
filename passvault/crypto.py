"""Key derivation, keystream encryption and message authentication.

All primitives come from the Python standard library:

* PBKDF2-HMAC-SHA256 for password stretching (``hashlib.pbkdf2_hmac``),
* HMAC-SHA256 in counter mode as a deterministic stream cipher,
* HMAC-SHA256 as the integrity tag (encrypt-then-MAC).

Key derivation is deliberately split so that a tampered header can never
make verification expensive:

* ``derive_mac_key(password, salt)`` -- a single HMAC-SHA256 over a domain
  separator and the salt.  It ignores all header fields, so the tag check
  is O(1) and runs *before* any attacker-controlled iteration count is
  used.  Password guessing is not made cheaper by this: a guess still has
  to produce the correct encryption key (full PBKDF2 over the header's
  iteration count) before the plaintext parses.
* ``derive_enc_key(password, salt, iterations)`` -- PBKDF2-HMAC-SHA256
  stretched to 32 bytes using the *authenticated* iteration count.

The keystream for offset ``i * 32`` is ``HMAC-SHA256(enc_key, nonce || i)``;
XORing it with the plaintext gives a length-preserving ciphertext.  The
tag covers the vault header (magic, KDF parameters, salt, nonce, length)
*and* the ciphertext, so any tampering -- including with KDF parameters --
is detected before any plaintext is returned to the caller.
"""
from __future__ import annotations

import hashlib
import hmac

__all__ = [
    "SALT_LEN",
    "NONCE_LEN",
    "MAC_CONTEXT",
    "derive_enc_key",
    "derive_mac_key",
    "keystream_xor",
    "mac",
    "verify_mac",
]

SALT_LEN = 16
NONCE_LEN = 16
MAC_CONTEXT = b"passvault-mac-v1"
_BLOCK = 32  # SHA-256 digest size / keystream block size


def derive_enc_key(password: bytes, salt: bytes, iterations: int) -> bytes:
    """Stretch ``password`` into a 32-byte encryption key (PBKDF2-HMAC-SHA256)."""
    if iterations < 1:
        raise ValueError("iterations must be >= 1")
    if not salt:
        raise ValueError("salt must be non-empty")
    return hashlib.pbkdf2_hmac("sha256", password, salt, iterations, dklen=32)


def derive_mac_key(password: bytes, salt: bytes) -> bytes:
    """Derive the 32-byte authentication key with one HMAC (header-independent).

    See the module docstring for why this is intentionally not PBKDF2: the
    MAC check must run before the (untrusted) header iteration count is
    honoured, otherwise a flipped header byte would burn CPU before the
    tampering is rejected.
    """
    if not salt:
        raise ValueError("salt must be non-empty")
    return hmac.new(password, MAC_CONTEXT + salt, hashlib.sha256).digest()


def keystream_xor(key: bytes, nonce: bytes, data: bytes) -> bytes:
    """XOR ``data`` with an HMAC-SHA256 counter-mode keystream.

    The function is its own inverse, so it encrypts and decrypts.
    Blocks are ``HMAC(key, nonce || counter)`` with an 8-byte big-endian
    counter, supporting inputs up to 2**32 blocks (128 GiB).
    """
    if len(nonce) == 0:
        raise ValueError("nonce must be non-empty")
    out = bytearray(len(data))
    counter = 0
    for i in range(0, len(data), _BLOCK):
        block = hmac.new(key, nonce + counter.to_bytes(8, "big"), hashlib.sha256).digest()
        chunk = data[i : i + _BLOCK]
        for j, byte in enumerate(chunk):
            out[i + j] = byte ^ block[j]
        counter += 1
    return bytes(out)


def mac(key: bytes, *parts: bytes) -> bytes:
    """HMAC-SHA256 over the concatenation of ``parts``."""
    digest = hmac.new(key, digestmod=hashlib.sha256)
    for part in parts:
        digest.update(part)
    return digest.digest()


def verify_mac(key: bytes, expected: bytes, *parts: bytes) -> bool:
    """Constant-time comparison of a computed tag against ``expected``."""
    return hmac.compare_digest(mac(key, *parts), expected)
