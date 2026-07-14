"""
Feature 0.1 - Vault Initialization & Unlock.

Owns the single Master-Passphrase-protected Data Encryption Key (DEK)
lifecycle for the whole Mini Vault instance:

    Master Passphrase --Argon2id (KDF)--> KEK
    KEK --AES-256-GCM--> encrypts a random 256-bit DEK
    DEK (plaintext) --lives in RAM only, while unlocked--> used by
        Feature 1 (KV) and Feature 2 (Transit) to encrypt everything else

On disk we only ever persist: the KDF salt, the encrypted DEK, and its
nonce. The plaintext DEK is never written anywhere. Every new process
starts "locked" by construction - there is no code path that restores
`_dek` from disk without the correct Master Passphrase being supplied
again.
"""
import base64
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from src.core import crypto, kdf  # noqa: E402 - relative import from sibling modules

DEFAULT_VAULT_META_PATH = Path("data") / "vault_meta.json"


class VaultError(Exception):
    """Base class for all vault-level (Feature 0.1) errors."""


class VaultLockedError(VaultError):
    """
    Raised by require_unlocked() whenever a Feature 1 / Feature 2
    operation is attempted while the vault is locked. Every such
    operation MUST call require_unlocked() before touching any crypto.
    """

    def __init__(self):
        super().__init__("VAULT_LOCKED")


class VaultAlreadyInitializedError(VaultError):
    """Raised when init_vault() is called but a vault already exists on disk."""


class InvalidMasterPassphraseError(VaultError):
    """
    Raised when unlock() is given a passphrase that fails to decrypt the
    stored DEK. Deliberately generic per the spec: wrong passphrase and
    (theoretically) a corrupted vault file look identical to the caller.
    """

    def __init__(self):
        super().__init__("Invalid master passphrase")


@dataclass
class VaultMeta:
    kdf: str
    kdf_salt_b64: str
    encrypted_dek_b64: str
    dek_nonce_b64: str
    status: str  # always written as "locked" - see note in _save_meta()

    def to_dict(self) -> dict:
        return {
            "kdf": self.kdf,
            "kdf_salt_b64": self.kdf_salt_b64,
            "encrypted_dek_b64": self.encrypted_dek_b64,
            "dek_nonce_b64": self.dek_nonce_b64,
            "status": self.status,
        }

    @staticmethod
    def from_dict(d: dict) -> "VaultMeta":
        return VaultMeta(
            kdf=d["kdf"],
            kdf_salt_b64=d["kdf_salt_b64"],
            encrypted_dek_b64=d["encrypted_dek_b64"],
            dek_nonce_b64=d["dek_nonce_b64"],
            status=d.get("status", "locked"),
        )


class VaultCore:
    """
    One VaultCore instance per running Mini Vault process. Holds the
    plaintext DEK in memory only after a successful unlock().
    """

    def __init__(self, meta_path: Path = DEFAULT_VAULT_META_PATH):
        self.meta_path = Path(meta_path)
        self._dek: Optional[bytes] = None  # plaintext DEK - in-memory ONLY, never persisted

    # ---- persistence -----------------------------------------------------

    def is_initialized(self) -> bool:
        return self.meta_path.exists()

    def _load_meta(self) -> VaultMeta:
        with open(self.meta_path, "r", encoding="utf-8") as f:
            return VaultMeta.from_dict(json.load(f))

    def _save_meta(self, meta: VaultMeta) -> None:
        # On-disk status is always "locked": a freshly written vault
        # file must never claim to be unlocked, since "unlocked" only
        # ever exists as an in-memory fact for this process.
        self.meta_path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = self.meta_path.with_suffix(".tmp")
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(meta.to_dict(), f, indent=2)
        os.replace(tmp_path, self.meta_path)  # atomic on POSIX

    # ---- Feature 0.1: init / unlock / lock --------------------------------

    def init_vault(self, master_passphrase: str) -> None:
        """
        First-run initialization only. Raises VaultAlreadyInitializedError
        if a vault meta file already exists - re-initializing over an
        existing vault would silently destroy access to everything
        already encrypted with the old DEK.
        """
        if self.is_initialized():
            raise VaultAlreadyInitializedError("Vault has already been initialized")

        salt = kdf.generate_salt()
        kek = kdf.derive_key(master_passphrase, salt)

        dek = os.urandom(32)  # brand-new random 256-bit DEK
        nonce, encrypted_dek = crypto.encrypt(kek, dek)

        meta = VaultMeta(
            kdf="argon2id",
            kdf_salt_b64=base64.b64encode(salt).decode("ascii"),
            encrypted_dek_b64=base64.b64encode(encrypted_dek).decode("ascii"),
            dek_nonce_b64=base64.b64encode(nonce).decode("ascii"),
            status="locked",
        )
        self._save_meta(meta)
        # The caller must call unlock() explicitly afterwards, exactly
        # like a real restart would require - init does NOT auto-unlock.

    def unlock(self, master_passphrase: str) -> None:
        """
        Re-derive the KEK from the given passphrase using the persisted
        salt, and attempt to decrypt the persisted DEK. On success, the
        plaintext DEK is kept in memory for the rest of this process's
        life (or until lock() is called).
        """
        if not self.is_initialized():
            raise VaultError("Vault has not been initialized yet")

        meta = self._load_meta()
        salt = base64.b64decode(meta.kdf_salt_b64)
        kek = kdf.derive_key(master_passphrase, salt)

        nonce = base64.b64decode(meta.dek_nonce_b64)
        encrypted_dek = base64.b64decode(meta.encrypted_dek_b64)

        try:
            dek = crypto.decrypt(kek, nonce, encrypted_dek)
        except crypto.DecryptionError:
            # Wrong passphrase -> GCM tag mismatch. Never disclose more
            # detail than this to the caller.
            raise InvalidMasterPassphraseError()

        self._dek = dek

    def lock(self) -> None:
        """Wipe the in-memory DEK reference, returning to the locked state."""
        self._dek = None

    def is_unlocked(self) -> bool:
        return self._dek is not None

    def require_unlocked(self) -> bytes:
        """
        Called by every Feature 1 (KV) / Feature 2 (Transit) operation
        BEFORE touching any encryption/decryption. Returns the current
        plaintext DEK, or raises VaultLockedError.
        """
        if self._dek is None:
            raise VaultLockedError()
        return self._dek