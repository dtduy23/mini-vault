"""
Key Derivation Function (KDF) helpers - Feature 0.1.

The Master Passphrase a human types has low entropy compared to a real
256-bit key. Argon2id turns that passphrase (plus a random salt) into a
proper 256-bit Key-Encryption-Key (KEK), while being deliberately slow
and memory-hard so brute-forcing the passphrase offline is expensive.

Only the salt is ever persisted to disk - the derived key and the
passphrase itself never touch disk.
"""
import os

from argon2.low_level import Type, hash_secret_raw

# Argon2id cost parameters. These control the time/memory tradeoff of
# brute-forcing the passphrase; tuned here to run well under a second
# on typical hardware while still being meaningfully slow.
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST_KIB = 65536  # 64 MiB
ARGON2_PARALLELISM = 4

DERIVED_KEY_LEN = 32  # 256-bit key, required for AES-256-GCM
SALT_LEN = 16


def generate_salt() -> bytes:
    """Cryptographically secure random salt, generated once at init time."""
    return os.urandom(SALT_LEN)


def derive_key(passphrase: str, salt: bytes) -> bytes:
    """
    Derive a 256-bit key from `passphrase` + `salt` using Argon2id.

    Deterministic: the same (passphrase, salt) pair always yields the
    same key, which is exactly what lets `unlock()` re-derive the same
    KEK on every restart as long as the correct passphrase is given.
    """
    return hash_secret_raw(
        secret=passphrase.encode("utf-8"),
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST_KIB,
        parallelism=ARGON2_PARALLELISM,
        hash_len=DERIVED_KEY_LEN,
        type=Type.ID,  # Argon2id variant specifically (mixes Argon2i + Argon2d)
    )