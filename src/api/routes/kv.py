"""
Feature 1 — Secure KV Storage routes.

Endpoints:
  PUT    /kv/{path}   — write (create or overwrite)
  GET    /kv/{path}   — read
  DELETE /kv/{path}   — delete
  GET    /kv/         — list all paths owned by caller

All paths must be  secret/<caller_email>/...
Access control is enforced by KVService before any crypto.
"""
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from typing import Any

from src.api.deps import get_kv, require_auth, require_vault_unlocked
from src.core.vault import VaultLockedError
from src.core.crypto import DecryptionError
from src.kv.service import KVService, NotFoundError, PermissionDeniedError

router = APIRouter(prefix="/kv", tags=["KV Storage (1.1 / 1.2)"])


# ── Models ────────────────────────────────────────────────────────────────────

class WriteRequest(BaseModel):
    data: Any   # any JSON-serialisable value


class WriteResponse(BaseModel):
    path:    str
    message: str


class ReadResponse(BaseModel):
    path: str
    data: Any


# ── Routes ────────────────────────────────────────────────────────────────────

@router.put("/{path:path}", response_model=WriteResponse)
def kv_write(
    path:          str,
    body:          WriteRequest,
    caller_email:  str       = Depends(require_auth),
    kv:            KVService = Depends(get_kv),
    _vault_check:  None      = Depends(require_vault_unlocked),
):
    """
    Encrypt and store any JSON value at the given path.
    Path must start with  secret/<your_email>/...
    """
    try:
        kv.write(path, body.data, caller_email)
    except PermissionDeniedError:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="PERMISSION_DENIED")
    except VaultLockedError:
        raise HTTPException(status_code=423, detail="VAULT_LOCKED")
    return WriteResponse(path=path, message="Written successfully")


@router.get("/{path:path}", response_model=ReadResponse)
def kv_read(
    path:          str,
    caller_email:  str       = Depends(require_auth),
    kv:            KVService = Depends(get_kv),
    _vault_check:  None      = Depends(require_vault_unlocked),
):
    """Decrypt and return the value stored at path."""
    try:
        data = kv.read(path, caller_email)
    except PermissionDeniedError:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="PERMISSION_DENIED")
    except NotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="NOT_FOUND")
    except DecryptionError:
        # Ciphertext tampered — refuse absolutely
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                            detail="Data integrity check failed: ciphertext may be corrupted")
    except VaultLockedError:
        raise HTTPException(status_code=423, detail="VAULT_LOCKED")
    return ReadResponse(path=path, data=data)


@router.delete("/{path:path}")
def kv_delete(
    path:          str,
    caller_email:  str       = Depends(require_auth),
    kv:            KVService = Depends(get_kv),
    _vault_check:  None      = Depends(require_vault_unlocked),
):
    """Permanently delete a secret."""
    try:
        kv.delete(path, caller_email)
    except PermissionDeniedError:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="PERMISSION_DENIED")
    except NotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="NOT_FOUND")
    except VaultLockedError:
        raise HTTPException(status_code=423, detail="VAULT_LOCKED")
    return {"path": path, "message": "Deleted"}


@router.get("/")
def kv_list(
    caller_email:  str       = Depends(require_auth),
    kv:            KVService = Depends(get_kv),
    _vault_check:  None      = Depends(require_vault_unlocked),
):
    """List all secret paths owned by the authenticated user."""
    try:
        paths = kv.list_paths(caller_email)
    except VaultLockedError:
        raise HTTPException(status_code=423, detail="VAULT_LOCKED")
    return {"paths": paths}
