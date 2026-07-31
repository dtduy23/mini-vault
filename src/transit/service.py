"""
Feature 2 — Transit Encryption & Signing Engine.

All named keys (AES-256 or asymmetric keypairs) are stored encrypted at
rest using the vault DEK.  The plaintext key material only ever lives in
RAM for the duration of a single encrypt/decrypt/sign/verify call.

Key types
─────────
  ENCRYPT_DECRYPT  →  AES-256 symmetric key (32 random bytes)
  SIGN_VERIFY      →  Ed25519 or RSA-2048 keypair

Ciphertext format (Feature 2.2)
────────────────────────────────
  vault:<key_name>:<base64(nonce[12] + ciphertext_with_tag)>

Access control (Feature 2.3)
────────────────────────────
  Each named key stores owner_email.  A caller can only use a key they
  own.  Rejections happen BEFORE any crypto, and the error is generic
  (does not reveal whether the key_name exists).

Signing (Feature 2.4)
──────────────────────
  Supported algorithms:
    ED25519                  – sign() works on RAW messages only
    RSASSA_PKCS1_V1_5_SHA_256 – supports both RAW and DIGEST message types
"""
import base64
import json
import logging
import os
from enum import StrEnum

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa, utils

from src.core import crypto
from src.core.vault import VaultCore
from src.storage.json_store import JsonStore

_logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────

CIPHERTEXT_PREFIX = "vault"
CIPHERTEXT_SEP    = ":"


class KeyUsage(StrEnum):
    ENCRYPT_DECRYPT = "ENCRYPT_DECRYPT"
    SIGN_VERIFY     = "SIGN_VERIFY"


class SigningAlgorithm(StrEnum):
    ED25519                   = "ED25519"
    RSASSA_PKCS1_V1_5_SHA_256 = "RSASSA_PKCS1_V1_5_SHA_256"


class MessageType(StrEnum):
    RAW    = "RAW"      # server will hash the message with SHA-256
    DIGEST = "DIGEST"   # client has already hashed; provide raw hash bytes


# ── Exceptions ────────────────────────────────────────────────────────────────

class TransitError(Exception):
    """Base class for transit errors."""


class KeyNotFoundError(TransitError):
    """Key name not found or caller doesn't own it (intentionally merged)."""


class KeyAlreadyExistsError(TransitError):
    """Raised when creating a key_name that already exists for this owner."""


class InvalidKeyUsageError(TransitError):
    """Raised when caller tries to use an ENCRYPT key for signing, or vice-versa."""


class InvalidCiphertextError(TransitError):
    """Raised when ciphertext format is malformed or truncated."""


# ── Helpers ───────────────────────────────────────────────────────────────────

def _encode_ciphertext(key_name: str, nonce: bytes, ct: bytes) -> str:
    blob = base64.b64encode(nonce + ct).decode("ascii")
    return f"{CIPHERTEXT_PREFIX}{CIPHERTEXT_SEP}{key_name}{CIPHERTEXT_SEP}{blob}"


def _decode_ciphertext(ciphertext: str) -> tuple[str, bytes, bytes]:
    """Returns (key_name, nonce, ciphertext_with_tag)."""
    parts = ciphertext.split(CIPHERTEXT_SEP, 2)
    if len(parts) != 3 or parts[0] != CIPHERTEXT_PREFIX:
        raise InvalidCiphertextError("Malformed ciphertext: expected vault:<key>:<b64>")
    key_name = parts[1]
    try:
        blob  = base64.b64decode(parts[2])
    except Exception as exc:
        raise InvalidCiphertextError("Malformed ciphertext: bad base64") from exc
    if len(blob) < 12:
        raise InvalidCiphertextError("Malformed ciphertext: too short")
    return key_name, blob[:12], blob[12:]


def _encrypt_bytes_with_dek(dek: bytes, raw: bytes) -> dict:
    """Return a JSON-safe dict with nonce_b64 and encrypted_b64."""
    nonce, enc = crypto.encrypt(dek, raw)
    return {
        "nonce_b64":     base64.b64encode(nonce).decode("ascii"),
        "encrypted_b64": base64.b64encode(enc).decode("ascii"),
    }


def _decrypt_bytes_with_dek(dek: bytes, record: dict) -> bytes:
    nonce = base64.b64decode(record["nonce_b64"])
    enc   = base64.b64decode(record["encrypted_b64"])
    return crypto.decrypt(dek, nonce, enc)


# ── Service ───────────────────────────────────────────────────────────────────

class TransitService:
    def __init__(self, vault: VaultCore, data_dir: str = "data") -> None:
        self._vault = vault
        self._store = JsonStore(f"{data_dir}/transit")

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _get_key_record(self, key_name: str, caller_email: str) -> dict:
        """
        Load key record and enforce ownership.
        Raises KeyNotFoundError (generic) so caller cannot tell whether
        the key exists but belongs to someone else.
        Logs the denied attempt with the requester's email and key_name (spec §2.3).
        """
        record = self._store.get(caller_email, key_name)
        if record is None:
            _logger.warning(
                "ACCESS_DENIED user=%r key_name=%r reason='key not found or ownership mismatch'",
                caller_email, key_name,
            )
            raise KeyNotFoundError("Key not found or access denied")
        return record

    def _require_key_usage(self, record: dict, expected: KeyUsage) -> None:
        if record["key_usage"] != expected:
            raise InvalidKeyUsageError(
                f"Key is {record['key_usage']}, not {expected}"
            )

    # ── 2.1 Named Key Management ──────────────────────────────────────────────

    def create_key(
        self,
        key_name: str,
        caller_email: str,
        key_usage: KeyUsage = KeyUsage.ENCRYPT_DECRYPT,
        signing_algorithm: SigningAlgorithm | None = None,
    ) -> None:
        """
        Create a new named key.
        Raises KeyAlreadyExistsError if the name is already in use by this owner.
        """
        if self._store.exists(caller_email, key_name):
            raise KeyAlreadyExistsError(f"Key already exists: {key_name}")

        dek = self._vault.require_unlocked()

        if key_usage == KeyUsage.ENCRYPT_DECRYPT:
            # Generate random AES-256 key material
            raw_key = os.urandom(32)
            record = {
                "key_name":   key_name,
                "owner_email": caller_email,
                "key_usage":  KeyUsage.ENCRYPT_DECRYPT,
                "signing_algorithm": None,
                **_encrypt_bytes_with_dek(dek, raw_key),
            }

        elif key_usage == KeyUsage.SIGN_VERIFY:
            if signing_algorithm is None:
                signing_algorithm = SigningAlgorithm.ED25519

            if signing_algorithm == SigningAlgorithm.ED25519:
                priv = ed25519.Ed25519PrivateKey.generate()
                priv_bytes = priv.private_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PrivateFormat.Raw,
                    encryption_algorithm=serialization.NoEncryption(),
                )
                pub_bytes = priv.public_key().public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw,
                )

            elif signing_algorithm == SigningAlgorithm.RSASSA_PKCS1_V1_5_SHA_256:
                priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
                priv_bytes = priv.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
                pub_bytes = priv.public_key().public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            else:
                raise ValueError(f"Unsupported signing algorithm: {signing_algorithm}")

            enc_priv = _encrypt_bytes_with_dek(dek, priv_bytes)
            record = {
                "key_name":            key_name,
                "owner_email":         caller_email,
                "key_usage":           KeyUsage.SIGN_VERIFY,
                "signing_algorithm":   signing_algorithm,
                "encrypted_b64":       enc_priv["encrypted_b64"],
                "nonce_b64":           enc_priv["nonce_b64"],
                "public_key_b64":      base64.b64encode(pub_bytes).decode("ascii"),
            }
        else:
            raise ValueError(f"Unknown key_usage: {key_usage}")

        self._store.put(caller_email, key_name, data=record)

    def list_keys(self, caller_email: str) -> list[dict]:
        """
        Return key metadata for all keys owned by caller.
        NEVER includes raw key material.
        """
        self._vault.require_unlocked()
        result = []
        for key_name in self._store.list_keys(caller_email):
            record = self._store.get(caller_email, key_name)
            if record:
                result.append({
                    "key_name":          record["key_name"],
                    "key_usage":         record["key_usage"],
                    "signing_algorithm": record.get("signing_algorithm"),
                })
        return result

    def revoke_key(self, key_name: str, caller_email: str) -> None:
        """Permanently delete a named key."""
        self._vault.require_unlocked()
        record = self._get_key_record(key_name, caller_email)  # ownership check
        self._store.delete(caller_email, key_name)

    # ── 2.2 Encrypt / Decrypt as a Service ───────────────────────────────────

    def encrypt(self, key_name: str, plaintext_b64: str, caller_email: str) -> str:
        """
        Encrypt plaintext_b64 using the named AES-256 key.
        Returns ciphertext string: vault:<key_name>:<base64_blob>
        """
        dek    = self._vault.require_unlocked()
        record = self._get_key_record(key_name, caller_email)
        self._require_key_usage(record, KeyUsage.ENCRYPT_DECRYPT)

        # Temporarily decrypt AES key material into RAM
        raw_key   = _decrypt_bytes_with_dek(dek, record)
        plaintext = base64.b64decode(plaintext_b64)

        nonce, ct = crypto.encrypt(raw_key, plaintext)
        return _encode_ciphertext(key_name, nonce, ct)

    def decrypt(self, ciphertext: str, caller_email: str) -> str:
        """
        Decrypt a vault ciphertext string.
        Returns base64-encoded plaintext.
        """
        dek = self._vault.require_unlocked()
        key_name, nonce, ct = _decode_ciphertext(ciphertext)

        record = self._get_key_record(key_name, caller_email)
        self._require_key_usage(record, KeyUsage.ENCRYPT_DECRYPT)

        raw_key   = _decrypt_bytes_with_dek(dek, record)
        plaintext = crypto.decrypt(raw_key, nonce, ct)
        return base64.b64encode(plaintext).decode("ascii")

    # ── 2.4 Sign / Verify as a Service ───────────────────────────────────────

    def sign(
        self,
        key_name: str,
        message_b64: str,
        message_type: MessageType,
        caller_email: str,
    ) -> str:
        """Sign a message; returns base64-encoded signature."""
        dek    = self._vault.require_unlocked()
        record = self._get_key_record(key_name, caller_email)
        self._require_key_usage(record, KeyUsage.SIGN_VERIFY)

        algo         = SigningAlgorithm(record["signing_algorithm"])
        message_bytes = base64.b64decode(message_b64)
        priv_bytes    = _decrypt_bytes_with_dek(dek, record)

        if algo == SigningAlgorithm.ED25519:
            priv = ed25519.Ed25519PrivateKey.from_private_bytes(priv_bytes)
            # Ed25519 only supports RAW (the library handles hashing internally)
            if message_type == MessageType.DIGEST:
                raise ValueError("ED25519 does not support DIGEST message_type")
            signature = priv.sign(message_bytes)

        elif algo == SigningAlgorithm.RSASSA_PKCS1_V1_5_SHA_256:
            priv = serialization.load_pem_private_key(priv_bytes, password=None)
            if message_type == MessageType.RAW:
                # Server hashes the message
                signature = priv.sign(message_bytes, padding.PKCS1v15(), hashes.SHA256())
            else:
                # DIGEST: client already computed SHA-256; verify length
                if len(message_bytes) != 32:
                    raise ValueError("DIGEST must be exactly 32 bytes (SHA-256 output)")
                signature = priv.sign(
                    message_bytes,
                    padding.PKCS1v15(),
                    utils.Prehashed(hashes.SHA256()),
                )
        else:
            raise ValueError(f"Unsupported algorithm: {algo}")

        return base64.b64encode(signature).decode("ascii")

    def verify(
        self,
        key_name: str,
        message_b64: str,
        message_type: MessageType,
        signature_b64: str,
        caller_email: str,
    ) -> dict:
        """
        Verify a signature.
        Returns {"key_name": str, "signature_valid": bool, "signing_algorithm": str}
        Never raises on bad signature — always returns signature_valid=False.
        """
        self._vault.require_unlocked()
        record = self._get_key_record(key_name, caller_email)
        self._require_key_usage(record, KeyUsage.SIGN_VERIFY)

        algo          = SigningAlgorithm(record["signing_algorithm"])
        message_bytes = base64.b64decode(message_b64)
        pub_bytes     = base64.b64decode(record["public_key_b64"])

        try:
            signature = base64.b64decode(signature_b64)
        except Exception:
            return {"key_name": key_name, "signature_valid": False, "signing_algorithm": algo}

        try:
            if algo == SigningAlgorithm.ED25519:
                pub = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
                pub.verify(signature, message_bytes)

            elif algo == SigningAlgorithm.RSASSA_PKCS1_V1_5_SHA_256:
                pub = serialization.load_pem_public_key(pub_bytes)
                if message_type == MessageType.RAW:
                    pub.verify(signature, message_bytes, padding.PKCS1v15(), hashes.SHA256())
                else:
                    if len(message_bytes) != 32:
                        return {"key_name": key_name, "signature_valid": False, "signing_algorithm": algo}
                    pub.verify(
                        signature,
                        message_bytes,
                        padding.PKCS1v15(),
                        utils.Prehashed(hashes.SHA256()),
                    )
            valid = True
        except Exception:
            valid = False

        return {
            "key_name":          key_name,
            "signature_valid":   valid,
            "signing_algorithm": algo,
        }
