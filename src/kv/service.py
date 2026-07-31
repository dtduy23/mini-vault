"""
Feature 1 — Secure KV Storage Engine.

Provides write / read / delete operations on secret paths.
Every secret is encrypted at rest with AES-256-GCM using the vault DEK.

Path rules (spec §1.2):
  • All paths MUST start with  secret/<owner_email>/
  • Access control is checked BEFORE any crypto operation.
  • A mismatched owner and a non-existent path return the same error
    to avoid leaking information about which paths exist.

On-disk format per secret:
  {
    "path":           "secret/alice@example.com/db",
    "nonce_b64":      "<12-byte nonce, base64>",
    "ciphertext_b64": "<AES-GCM ciphertext WITHOUT tag, base64>",
    "tag_b64":        "<16-byte AES-GCM authentication tag, base64>",
  }

The plaintext stored inside the ciphertext is the JSON-encoded `data`
value supplied by the caller.
"""
import base64
import json
import logging
from pathlib import Path

from src.core import crypto
from src.core.vault import VaultCore, VaultLockedError
from src.storage.json_store import JsonStore

_logger = logging.getLogger(__name__)

SECRET_PREFIX = "secret/"

# AES-GCM authentication tag is always 16 bytes (128 bits).
# The `cryptography` library appends the tag to the end of the ciphertext;
# we split it out so the on-disk schema is explicit.
GCM_TAG_LEN = 16


class KVError(Exception):
    """Base class for KV errors."""


class PermissionDeniedError(KVError):
    """
    Raised when the caller's token email doesn't match the path owner,
    OR when the path does not exist (intentionally indistinguishable).
    """


class NotFoundError(KVError):
    """Raised when a path genuinely does not exist after access control passes."""


def _validate_and_split(path: str, caller_email: str) -> tuple[str, str]:
    """
    Validate path format and ownership.

    Returns (owner_email, relative_key) if valid and caller owns it.
    Raises PermissionDeniedError otherwise, and logs the denied attempt
    with the requester's email and the denied path (spec §1.2).
    """
    if not path.startswith(SECRET_PREFIX):
        _logger.warning(
            "ACCESS_DENIED user=%r path=%r reason='missing secret/ prefix'",
            caller_email, path,
        )
        raise PermissionDeniedError("Access denied")

    rest = path[len(SECRET_PREFIX):]          # "alice@example.com/db"
    slash = rest.find("/")
    if slash < 1:
        _logger.warning(
            "ACCESS_DENIED user=%r path=%r reason='malformed path'",
            caller_email, path,
        )
        raise PermissionDeniedError("Access denied")

    owner_email  = rest[:slash]               # "alice@example.com"
    relative_key = rest[slash + 1:]           # "db"

    if not relative_key:
        _logger.warning(
            "ACCESS_DENIED user=%r path=%r reason='empty key segment'",
            caller_email, path,
        )
        raise PermissionDeniedError("Access denied")

    # Access control: caller email must match path owner (§1.2)
    if caller_email != owner_email:
        _logger.warning(
            "ACCESS_DENIED user=%r path=%r reason='ownership mismatch, owner=%r'",
            caller_email, path, owner_email,
        )
        raise PermissionDeniedError("Access denied")

    return owner_email, relative_key


class KVService:
    def __init__(self, vault: VaultCore, data_dir: str = "data") -> None:
        self._vault = vault
        self._store = JsonStore(f"{data_dir}/kv")

    # ── Write ─────────────────────────────────────────────────────────────────

    def write(self, path: str, data: object, caller_email: str) -> None:
        """
        Encrypt `data` (any JSON-serialisable value) and persist it.

        A fresh random nonce is generated on every write — even for the
        same path — so overwriting a secret does not reuse GCM state.
        The 16-byte GCM authentication tag is stored separately as tag_b64.
        """
        owner_email, relative_key = _validate_and_split(path, caller_email)

        dek       = self._vault.require_unlocked()       # raises VaultLockedError
        plaintext = json.dumps(data).encode("utf-8")

        nonce, ct_with_tag = crypto.encrypt(dek, plaintext)

        # Split off the 16-byte GCM authentication tag so it appears
        # as a distinct field in the on-disk JSON (spec §1.1 data contract).
        ciphertext = ct_with_tag[:-GCM_TAG_LEN]
        tag        = ct_with_tag[-GCM_TAG_LEN:]

        self._store.put(owner_email, relative_key, data={
            "path":           path,
            "nonce_b64":      base64.b64encode(nonce).decode("ascii"),
            "ciphertext_b64": base64.b64encode(ciphertext).decode("ascii"),
            "tag_b64":        base64.b64encode(tag).decode("ascii"),
        })

    # ── Read ──────────────────────────────────────────────────────────────────

    def read(self, path: str, caller_email: str) -> object:
        """
        Decrypt and return the stored value.

        Raises NotFoundError if the path doesn't exist (after access
        control passes).  Raises crypto.DecryptionError if the ciphertext
        has been tampered with — callers MUST NOT swallow this.
        """
        owner_email, relative_key = _validate_and_split(path, caller_email)

        record = self._store.get(owner_email, relative_key)
        if record is None:
            raise NotFoundError(f"Path not found: {path}")

        dek        = self._vault.require_unlocked()
        nonce      = base64.b64decode(record["nonce_b64"])
        ciphertext = base64.b64decode(record["ciphertext_b64"])
        tag        = base64.b64decode(record["tag_b64"])

        # Recombine ciphertext + tag before passing to AESGCM
        plaintext = crypto.decrypt(dek, nonce, ciphertext + tag)  # raises DecryptionError on tamper
        return json.loads(plaintext.decode("utf-8"))

    # ── Delete ────────────────────────────────────────────────────────────────

    def delete(self, path: str, caller_email: str) -> None:
        """Permanently delete a secret. Raises NotFoundError if absent."""
        owner_email, relative_key = _validate_and_split(path, caller_email)

        # Still require vault to be unlocked (consistent with spec §1.1)
        self._vault.require_unlocked()

        deleted = self._store.delete(owner_email, relative_key)
        if not deleted:
            raise NotFoundError(f"Path not found: {path}")

    # ── List (bonus) ──────────────────────────────────────────────────────────

    def list_paths(self, caller_email: str) -> list[str]:
        """Return all path stems owned by caller_email."""
        self._vault.require_unlocked()
        keys = self._store.list_keys(caller_email)
        return [f"{SECRET_PREFIX}{caller_email}/{k}" for k in keys]
