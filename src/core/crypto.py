"""
AES-256-GCM (AEAD) helpers, shared by every feature that encrypts data
at rest: the DEK itself (0.1), KV secrets (1.1), Transit named AES keys
(2.1), and Transit signing private keys (2.4).

GCM is an AEAD (Authenticated Encryption with Associated Data) mode: it
gives confidentiality AND integrity in a single primitive. Any
tampering with the ciphertext is detected at decrypt time via the
authentication tag - callers never need a separate integrity check, and
must never return data when that tag check fails.
"""
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_LEN = 12  # 96-bit nonce - the size recommended by NIST SP 800-38D for GCM


class DecryptionError(Exception):
    """
    Raised whenever AES-GCM authentication fails - covers both 'wrong
    key' and 'ciphertext was tampered with'. Callers must treat this as
    one generic failure and must NOT try to tell the two apart in any
    response sent back to a client.
    """


def encrypt(key: bytes, plaintext: bytes, associated_data: bytes | None = None) -> tuple[bytes, bytes]:
    """
    Encrypt `plaintext` with AES-256-GCM under `key`.

    Returns (nonce, ciphertext_with_tag) - the `cryptography` library
    appends the 16-byte auth tag to the end of the ciphertext for us.

    A fresh random nonce is generated on every call. Reusing a nonce
    with the same key is catastrophic for GCM (it breaks both
    confidentiality and authenticity), so this function never accepts
    a caller-supplied nonce.
    """
    if len(key) != 32:
        raise ValueError("AES-256-GCM requires a 32-byte key")
    nonce = os.urandom(NONCE_LEN)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, associated_data)
    return nonce, ciphertext


def decrypt(key: bytes, nonce: bytes, ciphertext: bytes, associated_data: bytes | None = None) -> bytes:
    """
    Decrypt + authenticate AES-256-GCM ciphertext.

    Raises DecryptionError on any authentication failure. Never returns
    partial or "probably correct" data - either the tag matches and the
    exact original plaintext comes back, or nothing comes back at all.
    """
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, associated_data)
    except InvalidTag as exc:
        raise DecryptionError("Decryption failed: invalid key or tampered data") from exc