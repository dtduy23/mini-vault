"""
Tests for Feature 0.1 — Vault Initialization & Unlock.

Acceptance criteria (from spec):
  ✓  DEK plaintext is never written to disk
  ✓  After restart (fresh VaultCore) vault is LOCKED until correct passphrase given
  ✓  Wrong passphrase raises generic error (no detail about why)
  ✓  Locked vault raises VAULT_LOCKED on require_unlocked()
  ✓  On-disk file only contains: kdf, kdf_salt_b64, encrypted_dek_b64, dek_nonce_b64, status
  ✓  Data contract: status is always written as "locked"
"""
import base64
import json
import os
import pathlib
import tempfile

import pytest

from src.core.vault import (
    InvalidMasterPassphraseError,
    VaultAlreadyInitializedError,
    VaultCore,
    VaultError,
    VaultLockedError,
)

PASSPHRASE = "correct-horse-battery-staple"
WRONG      = "wrong-passphrase"


@pytest.fixture()
def vault(tmp_path: pathlib.Path) -> VaultCore:
    """Fresh, uninitialised VaultCore backed by a temp directory."""
    return VaultCore(meta_path=tmp_path / "vault_meta.json")


@pytest.fixture()
def initialized_vault(vault: VaultCore) -> VaultCore:
    """VaultCore that has been initialized (but is still locked)."""
    vault.init_vault(PASSPHRASE)
    return vault


# ── Initialization ─────────────────────────────────────────────────────────────

class TestInit:
    def test_creates_meta_file(self, vault: VaultCore) -> None:
        vault.init_vault(PASSPHRASE)
        assert vault.meta_path.exists()

    def test_is_initialized_after_init(self, vault: VaultCore) -> None:
        assert not vault.is_initialized()
        vault.init_vault(PASSPHRASE)
        assert vault.is_initialized()

    def test_double_init_raises(self, initialized_vault: VaultCore) -> None:
        with pytest.raises(VaultAlreadyInitializedError):
            initialized_vault.init_vault(PASSPHRASE)

    def test_disk_contract_keys(self, initialized_vault: VaultCore) -> None:
        """On-disk JSON must have exactly the fields from the spec, nothing more."""
        data = json.loads(initialized_vault.meta_path.read_text())
        assert set(data.keys()) == {"kdf", "kdf_salt_b64", "encrypted_dek_b64", "dek_nonce_b64", "status"}

    def test_disk_contract_kdf_value(self, initialized_vault: VaultCore) -> None:
        data = json.loads(initialized_vault.meta_path.read_text())
        assert data["kdf"] == "argon2id"

    def test_disk_status_always_locked(self, initialized_vault: VaultCore) -> None:
        """Status field must be 'locked' on disk — even right after init."""
        data = json.loads(initialized_vault.meta_path.read_text())
        assert data["status"] == "locked"

    def test_dek_not_on_disk(self, initialized_vault: VaultCore) -> None:
        """
        The DEK plaintext must never appear on disk.
        We can't check all 2^256 possibilities, but we verify the on-disk file
        is not just a base64-encoded 32-byte random blob equal to any plaintext key.

        More importantly: we unlock, grab the DEK, then confirm it does NOT appear
        verbatim (as raw bytes or as base64) anywhere in the meta file.
        """
        initialized_vault.unlock(PASSPHRASE)
        dek = initialized_vault.require_unlocked()
        disk_text = initialized_vault.meta_path.read_text()

        # DEK as raw bytes should not appear anywhere in the file
        assert dek not in disk_text.encode()
        # DEK as base64 should not appear in the file
        assert base64.b64encode(dek).decode() not in disk_text


# ── Locked state ───────────────────────────────────────────────────────────────

class TestLockedState:
    def test_fresh_vault_is_locked(self, initialized_vault: VaultCore) -> None:
        """After init, vault must be LOCKED — not auto-unlocked."""
        assert not initialized_vault.is_unlocked()

    def test_fresh_process_is_locked(self, initialized_vault: VaultCore) -> None:
        """
        Simulate a 'restart': create a new VaultCore pointing at the same file.
        It must start locked even though init was called in the past.
        """
        fresh = VaultCore(meta_path=initialized_vault.meta_path)
        assert not fresh.is_unlocked()

    def test_require_unlocked_raises_when_locked(self, initialized_vault: VaultCore) -> None:
        with pytest.raises(VaultLockedError):
            initialized_vault.require_unlocked()

    def test_vault_locked_message(self, initialized_vault: VaultCore) -> None:
        exc = pytest.raises(VaultLockedError, initialized_vault.require_unlocked)
        assert str(exc.value) == "VAULT_LOCKED"


# ── Unlock ─────────────────────────────────────────────────────────────────────

class TestUnlock:
    def test_correct_passphrase_unlocks(self, initialized_vault: VaultCore) -> None:
        initialized_vault.unlock(PASSPHRASE)
        assert initialized_vault.is_unlocked()

    def test_require_unlocked_returns_dek(self, initialized_vault: VaultCore) -> None:
        initialized_vault.unlock(PASSPHRASE)
        dek = initialized_vault.require_unlocked()
        assert isinstance(dek, bytes)
        assert len(dek) == 32  # 256-bit DEK

    def test_dek_deterministic_across_unlocks(self, initialized_vault: VaultCore) -> None:
        """Same passphrase must produce the same DEK every time."""
        initialized_vault.unlock(PASSPHRASE)
        dek1 = initialized_vault.require_unlocked()
        initialized_vault.lock()
        initialized_vault.unlock(PASSPHRASE)
        dek2 = initialized_vault.require_unlocked()
        assert dek1 == dek2

    def test_dek_same_across_new_vault_core(self, initialized_vault: VaultCore) -> None:
        """Simulate restart: new process, same file → same DEK after unlock."""
        initialized_vault.unlock(PASSPHRASE)
        dek1 = initialized_vault.require_unlocked()

        fresh = VaultCore(meta_path=initialized_vault.meta_path)
        fresh.unlock(PASSPHRASE)
        dek2 = fresh.require_unlocked()
        assert dek1 == dek2

    def test_wrong_passphrase_raises_generic_error(self, initialized_vault: VaultCore) -> None:
        """Must raise InvalidMasterPassphraseError, not expose GCM details."""
        with pytest.raises(InvalidMasterPassphraseError):
            initialized_vault.unlock(WRONG)

    def test_wrong_passphrase_stays_locked(self, initialized_vault: VaultCore) -> None:
        try:
            initialized_vault.unlock(WRONG)
        except InvalidMasterPassphraseError:
            pass
        assert not initialized_vault.is_unlocked()

    def test_unlock_not_initialized_raises(self, vault: VaultCore) -> None:
        with pytest.raises(VaultError):
            vault.unlock(PASSPHRASE)


# ── Lock ───────────────────────────────────────────────────────────────────────

class TestLock:
    def test_lock_clears_dek(self, initialized_vault: VaultCore) -> None:
        initialized_vault.unlock(PASSPHRASE)
        assert initialized_vault.is_unlocked()
        initialized_vault.lock()
        assert not initialized_vault.is_unlocked()

    def test_require_unlocked_after_lock_raises(self, initialized_vault: VaultCore) -> None:
        initialized_vault.unlock(PASSPHRASE)
        initialized_vault.lock()
        with pytest.raises(VaultLockedError):
            initialized_vault.require_unlocked()

    def test_can_unlock_after_lock(self, initialized_vault: VaultCore) -> None:
        initialized_vault.unlock(PASSPHRASE)
        initialized_vault.lock()
        initialized_vault.unlock(PASSPHRASE)
        assert initialized_vault.is_unlocked()
