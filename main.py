"""
Mini Vault — CLI entry point (Feature 0.1: Vault Initialization & Unlock).

Usage:
    python main.py init            # First-run: set master passphrase, write vault_meta.json
    python main.py status          # Show whether vault is initialized
    python main.py unlock          # Prompt for passphrase, verify it can decrypt DEK
    python main.py lock            # Demonstrate in-process lock (wipes DEK from RAM)
    python main.py demo            # Full round-trip demo: init → unlock → lock → unlock wrong
"""
import getpass
import sys

from src.core.vault import (
    InvalidMasterPassphraseError,
    VaultAlreadyInitializedError,
    VaultCore,
    VaultError,
    VaultLockedError,
)

VAULT = VaultCore()  # singleton for this process; _dek lives here in RAM


def cmd_init() -> None:
    """Initialize the vault for the first time."""
    if VAULT.is_initialized():
        print("[ERROR] Vault is already initialized.")
        print("        Delete data/vault_meta.json to start fresh (WARNING: all data will be lost).")
        sys.exit(1)

    print("=== Vault Initialization ===")
    passphrase = getpass.getpass("Choose a master passphrase: ")
    confirm    = getpass.getpass("Confirm master passphrase: ")

    if passphrase != confirm:
        print("[ERROR] Passphrases do not match.")
        sys.exit(1)
    if len(passphrase) < 8:
        print("[ERROR] Passphrase must be at least 8 characters.")
        sys.exit(1)

    print("Deriving key with Argon2id (this takes a moment)…")
    try:
        VAULT.init_vault(passphrase)
    except VaultAlreadyInitializedError as exc:
        print(f"[ERROR] {exc}")
        sys.exit(1)

    print("✓ Vault initialized. DEK is encrypted on disk; vault is LOCKED.")
    print("  Run `python main.py unlock` to unlock it.")


def cmd_status() -> None:
    """Show whether the vault is initialized (does not require passphrase)."""
    if VAULT.is_initialized():
        print("✓ Vault is INITIALIZED (locked at startup — run `unlock` to decrypt DEK into RAM).")
    else:
        print("✗ Vault is NOT initialized — run `python main.py init` first.")


def cmd_unlock() -> None:
    """Prompt for passphrase and unlock the vault (decrypt DEK into RAM)."""
    if not VAULT.is_initialized():
        print("[ERROR] Vault is not initialized. Run `python main.py init` first.")
        sys.exit(1)

    passphrase = getpass.getpass("Master passphrase: ")
    print("Deriving key with Argon2id…")
    try:
        VAULT.unlock(passphrase)
    except InvalidMasterPassphraseError:
        print("[ERROR] Invalid master passphrase.")
        sys.exit(1)

    print("✓ Vault UNLOCKED. DEK is now in RAM (this process only).")
    print("  In a real server, DEK would stay here until `lock` or process exit.")


def cmd_lock() -> None:
    """Lock the vault (wipe DEK from RAM). Requires vault to be unlocked first."""
    if not VAULT.is_initialized():
        print("[ERROR] Vault is not initialized.")
        sys.exit(1)

    # Unlock first so we can demonstrate locking
    passphrase = getpass.getpass("Master passphrase (needed to unlock first): ")
    try:
        VAULT.unlock(passphrase)
    except InvalidMasterPassphraseError:
        print("[ERROR] Invalid master passphrase.")
        sys.exit(1)

    print(f"Before lock — unlocked: {VAULT.is_unlocked()}")
    VAULT.lock()
    print(f"After  lock — unlocked: {VAULT.is_unlocked()}")
    print("✓ Vault LOCKED. DEK wiped from RAM.")

    # Verify that require_unlocked() now raises VaultLockedError
    try:
        VAULT.require_unlocked()
        print("[BUG] require_unlocked() should have raised VaultLockedError!")
    except VaultLockedError:
        print("✓ require_unlocked() correctly raises VAULT_LOCKED after lock().")


def cmd_demo() -> None:
    """
    Full Feature 0.1 round-trip demo:
      init (if needed) → unlock correct → lock → unlock wrong → unlock correct again
    """
    print("=== Feature 0.1 Full Demo ===\n")

    # ── Step 1: init (skip if already done) ──────────────────────────────────
    if VAULT.is_initialized():
        print("[SKIP] Vault already initialized.")
    else:
        passphrase = getpass.getpass("[1/5] Choose master passphrase for demo: ")
        confirm    = getpass.getpass("      Confirm: ")
        if passphrase != confirm:
            print("[ERROR] Passphrases do not match.")
            sys.exit(1)
        print("      Deriving key with Argon2id…")
        VAULT.init_vault(passphrase)
        print("✓ [1/5] Vault initialized and LOCKED.\n")

    # ── Step 2: try to use DEK while locked ──────────────────────────────────
    print("[2/5] Trying require_unlocked() while locked…")
    try:
        VAULT.require_unlocked()
        print("[BUG] Should have raised VaultLockedError!")
    except VaultLockedError:
        print("✓ [2/5] Got VAULT_LOCKED as expected.\n")

    # ── Step 3: unlock with correct passphrase ────────────────────────────────
    passphrase = getpass.getpass("[3/5] Enter correct passphrase to unlock: ")
    print("      Deriving key with Argon2id…")
    try:
        VAULT.unlock(passphrase)
        dek = VAULT.require_unlocked()
        print(f"✓ [3/5] Vault UNLOCKED. DEK (first 8 bytes hex): {dek[:8].hex()}…\n")
    except InvalidMasterPassphraseError:
        print("[ERROR] Wrong passphrase — cannot continue demo.")
        sys.exit(1)

    # ── Step 4: lock ─────────────────────────────────────────────────────────
    VAULT.lock()
    print("[4/5] Vault LOCKED (DEK wiped from RAM).")
    try:
        VAULT.require_unlocked()
    except VaultLockedError:
        print("✓ [4/5] DEK is gone — VAULT_LOCKED confirmed.\n")

    # ── Step 5: unlock with wrong passphrase ─────────────────────────────────
    wrong = getpass.getpass("[5/5] Enter a WRONG passphrase to demonstrate rejection: ")
    print("      Deriving key with Argon2id…")
    try:
        VAULT.unlock(wrong)
        print("[BUG] Should have raised InvalidMasterPassphraseError!")
    except InvalidMasterPassphraseError:
        print("✓ [5/5] Wrong passphrase rejected with generic error (no detail leaked).\n")

    print("=== Demo complete — all Feature 0.1 acceptance criteria satisfied ===")


COMMANDS = {
    "init":   cmd_init,
    "status": cmd_status,
    "unlock": cmd_unlock,
    "lock":   cmd_lock,
    "demo":   cmd_demo,
}


def main() -> None:
    if len(sys.argv) < 2 or sys.argv[1] not in COMMANDS:
        print("Usage: python main.py <command>")
        print("Commands:", ", ".join(COMMANDS))
        sys.exit(1)
    COMMANDS[sys.argv[1]]()


if __name__ == "__main__":
    main()
