"""
Feature 2 — Transit Engine routes (key management + encrypt/decrypt + sign/verify).

Endpoints:
  POST   /transit/keys/{key_name}           — create named key
  GET    /transit/keys                      — list all keys (metadata only, NO raw key)
  DELETE /transit/keys/{key_name}           — revoke key
  POST   /transit/encrypt/{key_name}        — encrypt plaintext
  POST   /transit/decrypt                   — decrypt vault ciphertext
  POST   /transit/sign/{key_name}           — sign message
  POST   /transit/verify/{key_name}         — verify signature
"""
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from src.api.deps import get_transit, require_auth, require_vault_unlocked
from src.core.vault import VaultLockedError
from src.core.crypto import DecryptionError
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

router = APIRouter(prefix="/transit", tags=["Transit Engine (2.x)"])


# ── Models ────────────────────────────────────────────────────────────────────

class CreateKeyRequest(BaseModel):
    key_usage:         KeyUsage          = KeyUsage.ENCRYPT_DECRYPT
    signing_algorithm: SigningAlgorithm | None = None


class EncryptRequest(BaseModel):
    plaintext_b64: str   # base64-encoded plaintext


class EncryptResponse(BaseModel):
    ciphertext: str      # vault:<key_name>:<b64>


class DecryptRequest(BaseModel):
    ciphertext: str      # vault:<key_name>:<b64>


class DecryptResponse(BaseModel):
    plaintext_b64: str


class SignRequest(BaseModel):
    message_b64:  str
    message_type: MessageType = MessageType.RAW


class SignResponse(BaseModel):
    key_name:          str
    signature_b64:     str
    signing_algorithm: str


class VerifyRequest(BaseModel):
    message_b64:   str
    message_type:  MessageType = MessageType.RAW
    signature_b64: str


class VerifyResponse(BaseModel):
    key_name:          str
    signature_valid:   bool
    signing_algorithm: str


# ── Helper ────────────────────────────────────────────────────────────────────

def _handle_transit_errors(exc: Exception) -> HTTPException:
    if isinstance(exc, KeyNotFoundError):
        return HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                             detail="PERMISSION_DENIED: key not found or access denied")
    if isinstance(exc, KeyAlreadyExistsError):
        return HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))
    if isinstance(exc, InvalidKeyUsageError):
        return HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                             detail=f"InvalidKeyUsageException: {exc}")
    if isinstance(exc, InvalidCiphertextError):
        return HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                             detail=f"Invalid ciphertext: {exc}")
    if isinstance(exc, DecryptionError):
        return HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                             detail="Decryption failed: ciphertext tampered or wrong key")
    if isinstance(exc, VaultLockedError):
        return HTTPException(status_code=423, detail="VAULT_LOCKED")
    if isinstance(exc, ValueError):
        return HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    return HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                         detail="Internal error")


# ── 2.1 Key Management ────────────────────────────────────────────────────────

@router.post("/keys/{key_name}", status_code=status.HTTP_201_CREATED)
def create_key(
    key_name:     str,
    body:         CreateKeyRequest,
    caller_email: str            = Depends(require_auth),
    transit:      TransitService = Depends(get_transit),
    _vc:          None           = Depends(require_vault_unlocked),
):
    """
    Create a named key. key_usage=ENCRYPT_DECRYPT creates an AES-256 key;
    SIGN_VERIFY creates an Ed25519 (default) or RSA-2048 keypair.
    """
    try:
        transit.create_key(key_name, caller_email,
                           key_usage=body.key_usage,
                           signing_algorithm=body.signing_algorithm)
    except Exception as exc:
        raise _handle_transit_errors(exc)
    return {"key_name": key_name, "message": "Key created"}


@router.get("/keys")
def list_keys(
    caller_email: str            = Depends(require_auth),
    transit:      TransitService = Depends(get_transit),
    _vc:          None           = Depends(require_vault_unlocked),
):
    """Return key names and usages — NEVER raw key material."""
    try:
        keys = transit.list_keys(caller_email)
    except VaultLockedError:
        raise HTTPException(status_code=423, detail="VAULT_LOCKED")
    return {"keys": keys}


@router.delete("/keys/{key_name}")
def revoke_key(
    key_name:     str,
    caller_email: str            = Depends(require_auth),
    transit:      TransitService = Depends(get_transit),
    _vc:          None           = Depends(require_vault_unlocked),
):
    """Permanently delete a named key."""
    try:
        transit.revoke_key(key_name, caller_email)
    except Exception as exc:
        raise _handle_transit_errors(exc)
    return {"key_name": key_name, "message": "Key revoked"}


# ── 2.2 Encrypt / Decrypt ─────────────────────────────────────────────────────

@router.post("/encrypt/{key_name}", response_model=EncryptResponse)
def encrypt(
    key_name:     str,
    body:         EncryptRequest,
    caller_email: str            = Depends(require_auth),
    transit:      TransitService = Depends(get_transit),
    _vc:          None           = Depends(require_vault_unlocked),
):
    """Encrypt plaintext_b64 using the named ENCRYPT_DECRYPT key."""
    try:
        ct = transit.encrypt(key_name, body.plaintext_b64, caller_email)
    except Exception as exc:
        raise _handle_transit_errors(exc)
    return EncryptResponse(ciphertext=ct)


@router.post("/decrypt", response_model=DecryptResponse)
def decrypt(
    body:         DecryptRequest,
    caller_email: str            = Depends(require_auth),
    transit:      TransitService = Depends(get_transit),
    _vc:          None           = Depends(require_vault_unlocked),
):
    """Decrypt a vault ciphertext (vault:<key>:<b64>) back to base64 plaintext."""
    try:
        pt_b64 = transit.decrypt(body.ciphertext, caller_email)
    except Exception as exc:
        raise _handle_transit_errors(exc)
    return DecryptResponse(plaintext_b64=pt_b64)


# ── 2.4 Sign / Verify ─────────────────────────────────────────────────────────

@router.post("/sign/{key_name}", response_model=SignResponse)
def sign(
    key_name:     str,
    body:         SignRequest,
    caller_email: str            = Depends(require_auth),
    transit:      TransitService = Depends(get_transit),
    _vc:          None           = Depends(require_vault_unlocked),
):
    """Sign a message with the named SIGN_VERIFY key."""
    try:
        sig = transit.sign(key_name, body.message_b64, body.message_type, caller_email)
    except Exception as exc:
        raise _handle_transit_errors(exc)
    # Retrieve signing_algorithm from the key record for the response
    keys = transit.list_keys(caller_email)
    algo = next((k["signing_algorithm"] for k in keys if k["key_name"] == key_name), "UNKNOWN")
    return SignResponse(key_name=key_name, signature_b64=sig, signing_algorithm=algo)


@router.post("/verify/{key_name}", response_model=VerifyResponse)
def verify(
    key_name:     str,
    body:         VerifyRequest,
    caller_email: str            = Depends(require_auth),
    transit:      TransitService = Depends(get_transit),
    _vc:          None           = Depends(require_vault_unlocked),
):
    """
    Verify a signature. Always returns a structured result with signature_valid
    (true/false). Never crashes on bad input.
    """
    try:
        result = transit.verify(
            key_name, body.message_b64, body.message_type, body.signature_b64, caller_email
        )
    except KeyNotFoundError:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="PERMISSION_DENIED")
    except InvalidKeyUsageError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail=f"InvalidKeyUsageException: {exc}")
    except VaultLockedError:
        raise HTTPException(status_code=423, detail="VAULT_LOCKED")
    except Exception:
        # Any other error during verify → signature_valid = False (never crash)
        result = {"key_name": key_name, "signature_valid": False, "signing_algorithm": "UNKNOWN"}
    return VerifyResponse(**result)
