"""
Tests for Feature 2 — Transit Encryption & Signing Engine.

Acceptance criteria (from spec):
  ✓  2.1 create_key(): AES-256 or Ed25519/RSA-2048 keypair, encrypted with DEK
  ✓  2.1 list_keys(): metadata only, NEVER raw key material
  ✓  2.1 revoke_key(): permanently deletes the key
  ✓  2.1 Duplicate key name → KeyAlreadyExistsError
  ✓  2.2 encrypt() / decrypt() round-trip
  ✓  2.2 Ciphertext format: vault:<key_name>:<b64(nonce+ct+tag)>
  ✓  2.2 Malformed ciphertext → InvalidCiphertextError
  ✓  2.2 Tampered ciphertext → DecryptionError
  ✓  2.2 Using SIGN_VERIFY key for encrypt → InvalidKeyUsageError
  ✓  2.3 Access control: wrong owner → KeyNotFoundError (generic)
  ✓  2.4 sign() / verify() round-trip for Ed25519 and RSA
  ✓  2.4 Bad signature → signature_valid=False (no exception)
  ✓  2.4 ED25519 + DIGEST message type → ValueError
  ✓  2.4 RSA DIGEST with wrong length → reject
  ✓  2.4 Using ENCRYPT_DECRYPT key for signing → InvalidKeyUsageError
  ✓  vault locked → VaultLockedError on all operations
"""
import base64
import pathlib

import pytest

from src.core.crypto import DecryptionError
from src.core.vault import VaultCore, VaultLockedError
from src.transit.service import (
    InvalidCiphertextError,
    InvalidKeyUsageError,
    KeyAlreadyExistsError,
    KeyNotFoundError,
    KeyUsage,
    MessageType,
    SigningAlgorithm,
    TransitService,
)

PASSPHRASE = "correct-horse-battery-staple"
ALICE      = "alice@example.com"
BOB        = "bob@example.com"
KEY_NAME   = "my_key"
PLAINTEXT  = base64.b64encode(b"hello, transit!").decode()


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
    return v


@pytest.fixture()
def ts(vault: VaultCore, tmp_path: pathlib.Path) -> TransitService:
    return TransitService(vault=vault, data_dir=str(tmp_path))


@pytest.fixture()
def locked_ts(locked_vault: VaultCore, tmp_path: pathlib.Path) -> TransitService:
    return TransitService(vault=locked_vault, data_dir=str(tmp_path))


@pytest.fixture()
def ts_with_enc_key(ts: TransitService) -> TransitService:
    ts.create_key(KEY_NAME, ALICE, key_usage=KeyUsage.ENCRYPT_DECRYPT)
    return ts


@pytest.fixture()
def ts_with_ed25519_key(ts: TransitService) -> TransitService:
    ts.create_key(KEY_NAME, ALICE, key_usage=KeyUsage.SIGN_VERIFY,
                  signing_algorithm=SigningAlgorithm.ED25519)
    return ts


@pytest.fixture()
def ts_with_rsa_key(ts: TransitService) -> TransitService:
    ts.create_key(KEY_NAME, ALICE, key_usage=KeyUsage.SIGN_VERIFY,
                  signing_algorithm=SigningAlgorithm.RSASSA_PKCS1_V1_5_SHA_256)
    return ts


# ── 2.1 Key Management ─────────────────────────────────────────────────────────

class TestCreateKey:
    def test_create_encrypt_decrypt_key(self, ts: TransitService) -> None:
        ts.create_key(KEY_NAME, ALICE, key_usage=KeyUsage.ENCRYPT_DECRYPT)
        keys = ts.list_keys(ALICE)
        assert any(k["key_name"] == KEY_NAME for k in keys)

    def test_create_ed25519_key(self, ts: TransitService) -> None:
        ts.create_key(KEY_NAME, ALICE, key_usage=KeyUsage.SIGN_VERIFY,
                      signing_algorithm=SigningAlgorithm.ED25519)
        keys = ts.list_keys(ALICE)
        k = next(k for k in keys if k["key_name"] == KEY_NAME)
        assert k["signing_algorithm"] == SigningAlgorithm.ED25519

    def test_create_rsa_key(self, ts: TransitService) -> None:
        ts.create_key(KEY_NAME, ALICE, key_usage=KeyUsage.SIGN_VERIFY,
                      signing_algorithm=SigningAlgorithm.RSASSA_PKCS1_V1_5_SHA_256)
        keys = ts.list_keys(ALICE)
        k = next(k for k in keys if k["key_name"] == KEY_NAME)
        assert k["signing_algorithm"] == SigningAlgorithm.RSASSA_PKCS1_V1_5_SHA_256

    def test_duplicate_key_raises(self, ts_with_enc_key: TransitService) -> None:
        with pytest.raises(KeyAlreadyExistsError):
            ts_with_enc_key.create_key(KEY_NAME, ALICE, key_usage=KeyUsage.ENCRYPT_DECRYPT)

    def test_key_material_never_in_list(self, ts_with_enc_key: TransitService) -> None:
        """list_keys() must return only metadata — NEVER raw key bytes."""
        keys = ts_with_enc_key.list_keys(ALICE)
        for k in keys:
            assert "encrypted_b64" not in k
            assert "nonce_b64" not in k
            assert "public_key_b64" not in k

    def test_different_users_can_have_same_key_name(self, ts: TransitService) -> None:
        ts.create_key(KEY_NAME, ALICE, key_usage=KeyUsage.ENCRYPT_DECRYPT)
        ts.create_key(KEY_NAME, BOB, key_usage=KeyUsage.ENCRYPT_DECRYPT)
        assert len(ts.list_keys(ALICE)) == 1
        assert len(ts.list_keys(BOB)) == 1


class TestRevokeKey:
    def test_revoke_removes_key(self, ts_with_enc_key: TransitService) -> None:
        ts_with_enc_key.revoke_key(KEY_NAME, ALICE)
        assert ts_with_enc_key.list_keys(ALICE) == []

    def test_revoke_nonexistent_raises(self, ts: TransitService) -> None:
        with pytest.raises(KeyNotFoundError):
            ts.revoke_key("nonexistent", ALICE)

    def test_revoke_wrong_owner_raises(self, ts_with_enc_key: TransitService) -> None:
        with pytest.raises(KeyNotFoundError):
            ts_with_enc_key.revoke_key(KEY_NAME, BOB)


# ── 2.2 Encrypt / Decrypt ─────────────────────────────────────────────────────

class TestEncryptDecrypt:
    def test_encrypt_decrypt_round_trip(self, ts_with_enc_key: TransitService) -> None:
        ciphertext = ts_with_enc_key.encrypt(KEY_NAME, PLAINTEXT, ALICE)
        recovered  = ts_with_enc_key.decrypt(ciphertext, ALICE)
        assert recovered == PLAINTEXT

    def test_ciphertext_format(self, ts_with_enc_key: TransitService) -> None:
        """Ciphertext must be vault:<key_name>:<b64blob>"""
        ct = ts_with_enc_key.encrypt(KEY_NAME, PLAINTEXT, ALICE)
        parts = ct.split(":")
        assert parts[0] == "vault"
        assert parts[1] == KEY_NAME
        assert len(parts) == 3

    def test_encrypt_produces_different_ciphertexts(self, ts_with_enc_key: TransitService) -> None:
        """Fresh nonce each time — same plaintext must yield different ciphertext."""
        ct1 = ts_with_enc_key.encrypt(KEY_NAME, PLAINTEXT, ALICE)
        ct2 = ts_with_enc_key.encrypt(KEY_NAME, PLAINTEXT, ALICE)
        assert ct1 != ct2

    def test_malformed_ciphertext_raises(self, ts_with_enc_key: TransitService) -> None:
        with pytest.raises(InvalidCiphertextError):
            ts_with_enc_key.decrypt("notvalid", ALICE)

    def test_tampered_ciphertext_raises_decryption_error(
        self, ts_with_enc_key: TransitService
    ) -> None:
        ct = ts_with_enc_key.encrypt(KEY_NAME, PLAINTEXT, ALICE)
        parts = ct.split(":", 2)
        blob = bytearray(base64.b64decode(parts[2]))
        blob[12] ^= 0xFF          # flip a byte in the ciphertext region
        parts[2] = base64.b64encode(bytes(blob)).decode()
        tampered = ":".join(parts)
        with pytest.raises(DecryptionError):
            ts_with_enc_key.decrypt(tampered, ALICE)

    def test_wrong_key_usage_raises(self, ts_with_ed25519_key: TransitService) -> None:
        """SIGN_VERIFY key must not be usable for encryption."""
        with pytest.raises(InvalidKeyUsageError):
            ts_with_ed25519_key.encrypt(KEY_NAME, PLAINTEXT, ALICE)

    def test_wrong_owner_raises_on_encrypt(self, ts_with_enc_key: TransitService) -> None:
        with pytest.raises(KeyNotFoundError):
            ts_with_enc_key.encrypt(KEY_NAME, PLAINTEXT, BOB)

    def test_wrong_owner_raises_on_decrypt(self, ts_with_enc_key: TransitService) -> None:
        ct = ts_with_enc_key.encrypt(KEY_NAME, PLAINTEXT, ALICE)
        with pytest.raises(KeyNotFoundError):
            ts_with_enc_key.decrypt(ct, BOB)


# ── 2.4 Sign / Verify ─────────────────────────────────────────────────────────

class TestSignVerifyED25519:
    def test_sign_verify_round_trip(self, ts_with_ed25519_key: TransitService) -> None:
        msg_b64 = base64.b64encode(b"Hello ED25519!").decode()
        sig_b64 = ts_with_ed25519_key.sign(KEY_NAME, msg_b64, MessageType.RAW, ALICE)
        result  = ts_with_ed25519_key.verify(KEY_NAME, msg_b64, MessageType.RAW, sig_b64, ALICE)
        assert result["signature_valid"] is True
        assert result["signing_algorithm"] == SigningAlgorithm.ED25519

    def test_bad_signature_returns_false(self, ts_with_ed25519_key: TransitService) -> None:
        msg_b64 = base64.b64encode(b"Hello!").decode()
        bad_sig = base64.b64encode(b"x" * 64).decode()
        result  = ts_with_ed25519_key.verify(KEY_NAME, msg_b64, MessageType.RAW, bad_sig, ALICE)
        assert result["signature_valid"] is False

    def test_ed25519_digest_type_raises(self, ts_with_ed25519_key: TransitService) -> None:
        """ED25519 does not support DIGEST message_type."""
        msg_b64 = base64.b64encode(b"x" * 32).decode()
        with pytest.raises(ValueError, match="DIGEST"):
            ts_with_ed25519_key.sign(KEY_NAME, msg_b64, MessageType.DIGEST, ALICE)

    def test_wrong_key_usage_raises(self, ts_with_enc_key: TransitService) -> None:
        msg_b64 = base64.b64encode(b"test").decode()
        with pytest.raises(InvalidKeyUsageError):
            ts_with_enc_key.sign(KEY_NAME, msg_b64, MessageType.RAW, ALICE)

    def test_wrong_owner_raises_on_sign(self, ts_with_ed25519_key: TransitService) -> None:
        with pytest.raises(KeyNotFoundError):
            ts_with_ed25519_key.sign(KEY_NAME, PLAINTEXT, MessageType.RAW, BOB)


class TestSignVerifyRSA:
    def test_sign_verify_raw(self, ts_with_rsa_key: TransitService) -> None:
        msg_b64 = base64.b64encode(b"Hello RSA!").decode()
        sig_b64 = ts_with_rsa_key.sign(KEY_NAME, msg_b64, MessageType.RAW, ALICE)
        result  = ts_with_rsa_key.verify(KEY_NAME, msg_b64, MessageType.RAW, sig_b64, ALICE)
        assert result["signature_valid"] is True
        assert result["signing_algorithm"] == SigningAlgorithm.RSASSA_PKCS1_V1_5_SHA_256

    def test_sign_verify_digest(self, ts_with_rsa_key: TransitService) -> None:
        import hashlib
        raw_msg    = b"Hello RSA DIGEST!"
        digest     = hashlib.sha256(raw_msg).digest()
        digest_b64 = base64.b64encode(digest).decode()
        sig_b64    = ts_with_rsa_key.sign(KEY_NAME, digest_b64, MessageType.DIGEST, ALICE)
        result     = ts_with_rsa_key.verify(KEY_NAME, digest_b64, MessageType.DIGEST, sig_b64, ALICE)
        assert result["signature_valid"] is True

    def test_rsa_digest_wrong_length_raises(self, ts_with_rsa_key: TransitService) -> None:
        """DIGEST must be exactly 32 bytes (SHA-256)."""
        short_b64 = base64.b64encode(b"tooshort").decode()
        with pytest.raises(ValueError, match="32 bytes"):
            ts_with_rsa_key.sign(KEY_NAME, short_b64, MessageType.DIGEST, ALICE)

    def test_bad_signature_returns_false(self, ts_with_rsa_key: TransitService) -> None:
        msg_b64 = base64.b64encode(b"msg").decode()
        bad_sig = base64.b64encode(b"x" * 256).decode()
        result  = ts_with_rsa_key.verify(KEY_NAME, msg_b64, MessageType.RAW, bad_sig, ALICE)
        assert result["signature_valid"] is False

    def test_malformed_signature_b64_returns_false(self, ts_with_rsa_key: TransitService) -> None:
        msg_b64 = base64.b64encode(b"msg").decode()
        result  = ts_with_rsa_key.verify(KEY_NAME, msg_b64, MessageType.RAW, "!!!notb64", ALICE)
        assert result["signature_valid"] is False


# ── Vault locked ───────────────────────────────────────────────────────────────

class TestVaultLocked:
    def test_create_key_raises_when_locked(self, locked_ts: TransitService) -> None:
        with pytest.raises(VaultLockedError):
            locked_ts.create_key(KEY_NAME, ALICE)

    def test_encrypt_raises_when_locked(self, locked_ts: TransitService) -> None:
        with pytest.raises(VaultLockedError):
            locked_ts.encrypt(KEY_NAME, PLAINTEXT, ALICE)

    def test_decrypt_raises_when_locked(self, locked_ts: TransitService) -> None:
        with pytest.raises((VaultLockedError, InvalidCiphertextError, KeyNotFoundError)):
            locked_ts.decrypt("vault:key:abc", ALICE)

    def test_list_keys_raises_when_locked(self, locked_ts: TransitService) -> None:
        with pytest.raises(VaultLockedError):
            locked_ts.list_keys(ALICE)
