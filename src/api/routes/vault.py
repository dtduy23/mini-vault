"""
Feature 0.1 — Vault init / unlock / lock / status routes.
"""
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from src.api.deps import get_vault, require_auth
from src.core.vault import (
    VaultAlreadyInitializedError,
    VaultCore,
    VaultError,
    InvalidMasterPassphraseError,
)

router = APIRouter(prefix="/vault", tags=["Vault (0.1)"])


# ── Request / Response models ─────────────────────────────────────────────────

class InitRequest(BaseModel):
    master_passphrase: str = Field(..., min_length=8)


class UnlockRequest(BaseModel):
    master_passphrase: str


class VaultStatusResponse(BaseModel):
    initialized: bool
    unlocked:    bool


# ── Routes ────────────────────────────────────────────────────────────────────

@router.post("/init", status_code=status.HTTP_201_CREATED)
def vault_init(
    body:  InitRequest,
    vault: VaultCore = Depends(get_vault),
):
    """
    First-run: set the master passphrase, generate and encrypt the DEK.
    Returns 409 if the vault has already been initialized.
    Does NOT auto-unlock — call /vault/unlock afterward.
    """
    try:
        vault.init_vault(body.master_passphrase)
    except VaultAlreadyInitializedError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Vault already initialized",
        )
    return {"message": "Vault initialized. Call /vault/unlock to unlock."}


@router.post("/unlock")
def vault_unlock(
    body:  UnlockRequest,
    vault: VaultCore = Depends(get_vault),
):
    """
    Re-derive the KEK, decrypt the DEK into RAM. Returns 401 on wrong passphrase.
    """
    if not vault.is_initialized():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Vault is not initialized. Call /vault/init first.",
        )
    try:
        vault.unlock(body.master_passphrase)
    except InvalidMasterPassphraseError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid master passphrase",
        )
    return {"message": "Vault unlocked. DEK is in RAM."}


@router.post("/lock")
def vault_lock(vault: VaultCore = Depends(get_vault)):
    """Wipe the DEK from RAM. Vault returns to locked state."""
    vault.lock()
    return {"message": "Vault locked. DEK wiped from RAM."}


@router.get("/status", response_model=VaultStatusResponse)
def vault_status(vault: VaultCore = Depends(get_vault)):
    return VaultStatusResponse(
        initialized=vault.is_initialized(),
        unlocked=vault.is_unlocked(),
    )
