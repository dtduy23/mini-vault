"""
Tests for Feature 1 — Secure KV Storage Engine.

Acceptance criteria (from spec):
  ✓  write(): encrypts at rest with DEK, fresh nonce each time
  ✓  write(): on-disk record has path, nonce_b64, ciphertext_b64, tag_b64
  ✓  read(): decrypts correctly
  ✓  read(): detects ciphertext tampering (GCM tag fails → DecryptionError)
  ✓  delete(): removes the record permanently
  ✓  Access control: wrong email → PermissionDeniedError (logged)
  ✓  Path without secret/ prefix → PermissionDeniedError
  ✓  Path with empty key → PermissionDeniedError
  ✓  vault locked → VaultLockedError on every operation
  ✓  read non-existent path → NotFoundError
  ✓  delete non-existent path → NotFoundError
  ✓  Overwrite uses fresh nonce (nonce should differ across writes)
"""
import base64
import json
import pathlib

import pytest

from src.core.crypto import DecryptionError
from src.core.vault import VaultCore, VaultLockedError
from src.kv.service import KVService, NotFoundError, PermissionDeniedError

PASSPHRASE = "correct-horse-battery-staple"
ALICE      = "alice@example.com"
BOB        = "bob@example.com"
ALICE_PATH = f"secret/{ALICE}/mydb"
BOB_PATH   = f"secret/{BOB}/mydb"
DATA       = {"username": "alice", "password": "s3cr3t"}


@pytest.fixture()
def vault(tmp_path: pathlib.Path) -> VaultCore:
    v = VaultCore(meta_path=tmp_path / "vault_meta.json")
    v.init_vault(PASSPHRASE)
    v.unlock(PASSPHRASE)
    return v


@pytest.fixture()
def locked_vault(tmp_path: pathlib.Path) -> VaultCore:
    v = VaultCore(meta_path=tmp_path / "vault_meta.json")
    v.init_vault(PASSPHRASE)
    # deliberately NOT unlocked
    return v


@pytest.fixture()
def kv(vault: VaultCore, tmp_path: pathlib.Path) -> KVService:
    return KVService(vault=vault, data_dir=str(tmp_path))


@pytest.fixture()
def locked_kv(locked_vault: VaultCore, tmp_path: pathlib.Path) -> KVService:
    return KVService(vault=locked_vault, data_dir=str(tmp_path))


# ── Write / Read round-trip ────────────────────────────────────────────────────

class TestWriteRead:
    def test_write_then_read_returns_same_data(self, kv: KVService) -> None:
        kv.write(ALICE_PATH, DATA, ALICE)
        result = kv.read(ALICE_PATH, ALICE)
        assert result == DATA

    def test_write_scalar_value(self, kv: KVService) -> None:
        kv.write(ALICE_PATH, "hello world", ALICE)
        assert kv.read(ALICE_PATH, ALICE) == "hello world"

    def test_write_number_value(self, kv: KVService) -> None:
        kv.write(ALICE_PATH, 42, ALICE)
        assert kv.read(ALICE_PATH, ALICE) == 42

    def test_write_list_value(self, kv: KVService) -> None:
        kv.write(ALICE_PATH, [1, 2, 3], ALICE)
        assert kv.read(ALICE_PATH, ALICE) == [1, 2, 3]

    def test_overwrite_returns_new_value(self, kv: KVService) -> None:
        kv.write(ALICE_PATH, DATA, ALICE)
        kv.write(ALICE_PATH, {"new": "data"}, ALICE)
        assert kv.read(ALICE_PATH, ALICE) == {"new": "data"}

    def test_overwrite_uses_fresh_nonce(self, kv: KVService, tmp_path: pathlib.Path) -> None:
        """Each write must generate a distinct nonce (never reuse GCM state)."""
        kv.write(ALICE_PATH, DATA, ALICE)
        store_path = tmp_path / "kv" / ALICE / "mydb.json"
        rec1 = json.loads(store_path.read_text())["nonce_b64"]

        kv.write(ALICE_PATH, {"v": 2}, ALICE)
        rec2 = json.loads(store_path.read_text())["nonce_b64"]

        assert rec1 != rec2, "Same nonce reused — GCM catastrophic failure risk!"


# ── On-disk data contract ──────────────────────────────────────────────────────

class TestOnDiskContract:
    def test_disk_has_tag_b64(self, kv: KVService, tmp_path: pathlib.Path) -> None:
        """On-disk JSON must contain a separate tag_b64 field (spec §1.1)."""
        kv.write(ALICE_PATH, DATA, ALICE)
        store_path = tmp_path / "kv" / ALICE / "mydb.json"
        record = json.loads(store_path.read_text())
        assert "tag_b64" in record, "Missing tag_b64 in on-disk record"

    def test_disk_has_required_fields(self, kv: KVService, tmp_path: pathlib.Path) -> None:
        kv.write(ALICE_PATH, DATA, ALICE)
        store_path = tmp_path / "kv" / ALICE / "mydb.json"
        record = json.loads(store_path.read_text())
        assert "path" in record
        assert "nonce_b64" in record
        assert "ciphertext_b64" in record
        assert "tag_b64" in record

    def test_disk_does_not_contain_plaintext(self, kv: KVService, tmp_path: pathlib.Path) -> None:
        kv.write(ALICE_PATH, DATA, ALICE)
        store_path = tmp_path / "kv" / ALICE / "mydb.json"
        disk_text = store_path.read_text()
        assert DATA["password"] not in disk_text

    def test_tag_is_16_bytes(self, kv: KVService, tmp_path: pathlib.Path) -> None:
        """GCM tag must be exactly 16 bytes (128 bits)."""
        kv.write(ALICE_PATH, DATA, ALICE)
        store_path = tmp_path / "kv" / ALICE / "mydb.json"
        record = json.loads(store_path.read_text())
        tag_bytes = base64.b64decode(record["tag_b64"])
        assert len(tag_bytes) == 16


# ── Tamper detection ───────────────────────────────────────────────────────────

class TestTamperDetection:
    def test_tampered_ciphertext_raises_decryption_error(
        self, kv: KVService, tmp_path: pathlib.Path
    ) -> None:
        """Any modification to ciphertext must be caught by GCM tag verification."""
        kv.write(ALICE_PATH, DATA, ALICE)
        store_path = tmp_path / "kv" / ALICE / "mydb.json"
        record = json.loads(store_path.read_text())

        # Flip a byte in the ciphertext
        ct_bytes = bytearray(base64.b64decode(record["ciphertext_b64"]))
        ct_bytes[0] ^= 0xFF
        record["ciphertext_b64"] = base64.b64encode(bytes(ct_bytes)).decode()
        store_path.write_text(json.dumps(record))

        with pytest.raises(DecryptionError):
            kv.read(ALICE_PATH, ALICE)

    def test_tampered_tag_raises_decryption_error(
        self, kv: KVService, tmp_path: pathlib.Path
    ) -> None:
        """Any modification to the tag must also fail."""
        kv.write(ALICE_PATH, DATA, ALICE)
        store_path = tmp_path / "kv" / ALICE / "mydb.json"
        record = json.loads(store_path.read_text())

        tag_bytes = bytearray(base64.b64decode(record["tag_b64"]))
        tag_bytes[0] ^= 0xFF
        record["tag_b64"] = base64.b64encode(bytes(tag_bytes)).decode()
        store_path.write_text(json.dumps(record))

        with pytest.raises(DecryptionError):
            kv.read(ALICE_PATH, ALICE)


# ── Delete ─────────────────────────────────────────────────────────────────────

class TestDelete:
    def test_delete_removes_secret(self, kv: KVService) -> None:
        kv.write(ALICE_PATH, DATA, ALICE)
        kv.delete(ALICE_PATH, ALICE)
        with pytest.raises(NotFoundError):
            kv.read(ALICE_PATH, ALICE)

    def test_delete_nonexistent_raises(self, kv: KVService) -> None:
        with pytest.raises(NotFoundError):
            kv.delete(ALICE_PATH, ALICE)


# ── Access control ─────────────────────────────────────────────────────────────

class TestAccessControl:
    def test_wrong_email_raises_permission_denied_on_write(self, kv: KVService) -> None:
        """Bob must not be able to write to Alice's path."""
        with pytest.raises(PermissionDeniedError):
            kv.write(ALICE_PATH, DATA, BOB)

    def test_wrong_email_raises_permission_denied_on_read(self, kv: KVService) -> None:
        kv.write(ALICE_PATH, DATA, ALICE)
        with pytest.raises(PermissionDeniedError):
            kv.read(ALICE_PATH, BOB)

    def test_wrong_email_raises_permission_denied_on_delete(self, kv: KVService) -> None:
        kv.write(ALICE_PATH, DATA, ALICE)
        with pytest.raises(PermissionDeniedError):
            kv.delete(ALICE_PATH, BOB)

    def test_missing_secret_prefix_raises(self, kv: KVService) -> None:
        with pytest.raises(PermissionDeniedError):
            kv.write(f"data/{ALICE}/key", DATA, ALICE)

    def test_empty_key_raises(self, kv: KVService) -> None:
        with pytest.raises(PermissionDeniedError):
            kv.write(f"secret/{ALICE}/", DATA, ALICE)

    def test_nonexistent_path_after_correct_email_raises_not_found(
        self, kv: KVService
    ) -> None:
        """A path that doesn't exist but is correctly owned → NotFoundError (not PermissionDenied)."""
        with pytest.raises(NotFoundError):
            kv.read(ALICE_PATH, ALICE)

    def test_access_denied_before_unlock_check(self, locked_kv: KVService) -> None:
        """Permission check must come before vault-locked check."""
        # Bob trying Alice's path → PermissionDenied (not VaultLockedError)
        with pytest.raises(PermissionDeniedError):
            locked_kv.write(ALICE_PATH, DATA, BOB)


# ── Vault locked ───────────────────────────────────────────────────────────────

class TestVaultLocked:
    def test_write_raises_when_locked(self, locked_kv: KVService) -> None:
        with pytest.raises(VaultLockedError):
            locked_kv.write(ALICE_PATH, DATA, ALICE)

    def test_read_raises_when_locked(self, tmp_path: pathlib.Path) -> None:
        """
        read() must raise VaultLockedError. We first write data via an
        unlocked vault, then lock it and confirm read() is blocked.
        """
        v = VaultCore(meta_path=tmp_path / "vm2.json")
        v.init_vault(PASSPHRASE)
        v.unlock(PASSPHRASE)
        kv_unlocked = KVService(vault=v, data_dir=str(tmp_path / "data2"))
        kv_unlocked.write(ALICE_PATH, DATA, ALICE)
        v.lock()   # lock after data is in place
        with pytest.raises(VaultLockedError):
            kv_unlocked.read(ALICE_PATH, ALICE)

    def test_delete_raises_when_locked(self, locked_kv: KVService) -> None:
        with pytest.raises(VaultLockedError):
            locked_kv.delete(ALICE_PATH, ALICE)


# ── List ───────────────────────────────────────────────────────────────────────

class TestList:
    def test_list_paths_returns_owned_paths(self, kv: KVService) -> None:
        kv.write(f"secret/{ALICE}/db", {"a": 1}, ALICE)
        kv.write(f"secret/{ALICE}/api_key", {"k": "v"}, ALICE)
        paths = kv.list_paths(ALICE)
        assert f"secret/{ALICE}/db" in paths
        assert f"secret/{ALICE}/api_key" in paths

    def test_list_paths_empty_for_new_user(self, kv: KVService) -> None:
        assert kv.list_paths(ALICE) == []
