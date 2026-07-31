"""
Shared FastAPI dependency providers.

The VaultCore, AuthService, KVService, and TransitService instances are
module-level singletons — one per server process. FastAPI's Depends()
system injects them into route handlers.

Important: all services share the SAME VaultCore instance so that
unlocking the vault in one request makes the DEK available to all
subsequent requests within the same process.
"""
from functools import lru_cache

from fastapi import Header, HTTPException, status

from src.auth.service import AuthService, TokenExpiredError, AccountLockedError
from src.core.vault import VaultCore, VaultLockedError
from src.kv.service import KVService
from src.transit.service import TransitService

# ── Singleton instances (module-level, shared across requests) ─────────────────

_vault   = VaultCore()
_auth    = AuthService()
_kv      = KVService(_vault)
_transit = TransitService(_vault)


def get_vault() -> VaultCore:
    return _vault


def get_auth() -> AuthService:
    return _auth


def get_kv() -> KVService:
    return _kv


def get_transit() -> TransitService:
    return _transit


# ── Auth guard ────────────────────────────────────────────────────────────────

def get_current_email(
    authorization: str | None = Header(default=None),
    auth: AuthService = None,   # injected below via Depends in routes
) -> str:
    """
    Extract and verify the Bearer token from the Authorization header.
    Returns the owner email on success.

    Raises HTTP 401 if missing/invalid/expired.
    This dependency is used directly in routes; use require_auth() instead.
    """
    raise NotImplementedError("Use require_auth dependency in routes")


def require_auth(authorization: str | None = Header(default=None)) -> str:
    """
    FastAPI dependency: validate Bearer token, return email.
    Must be used with Depends() in route handlers.
    """
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="UNAUTHENTICATED: Missing or malformed Authorization header",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = authorization.removeprefix("Bearer ").strip()
    try:
        email = _auth.verify_token(token)
    except TokenExpiredError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"UNAUTHENTICATED: {exc}",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return email


def require_vault_unlocked() -> None:
    """Dependency: raise 423 Locked if vault is not unlocked."""
    if not _vault.is_unlocked():
        raise HTTPException(
            status_code=423,   # HTTP 423 Locked
            detail="VAULT_LOCKED: unlock the vault first",
        )
