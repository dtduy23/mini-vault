"""
Feature 0.2 — User registration, login, logout routes.
"""
from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel, EmailStr, Field

from src.api.deps import get_auth, require_auth
from src.auth.service import (
    AccountLockedError,
    AuthService,
    AuthenticationError,
    UserAlreadyExistsError,
)

router = APIRouter(prefix="/auth", tags=["Auth (0.2)"])


# ── Models ────────────────────────────────────────────────────────────────────

class RegisterRequest(BaseModel):
    email:              EmailStr
    passphrase:         str = Field(..., min_length=8)
    confirm_passphrase: str


class LoginRequest(BaseModel):
    email:      EmailStr
    passphrase: str


class LoginResponse(BaseModel):
    token:      str
    expires_at: str


# ── Routes ────────────────────────────────────────────────────────────────────

@router.post("/register", status_code=status.HTTP_201_CREATED)
def register(body: RegisterRequest, auth: AuthService = Depends(get_auth)):
    """Register a new user. 409 if email already exists."""
    try:
        auth.register(str(body.email), body.passphrase, body.confirm_passphrase)
    except UserAlreadyExistsError:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                            detail="Email already registered")
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    return {"message": "User registered successfully"}


@router.post("/login", response_model=LoginResponse)
def login(body: LoginRequest, auth: AuthService = Depends(get_auth)):
    """
    Login with email + passphrase.
    Returns 30-minute session token.
    Returns 423 after 5 consecutive failed attempts (locked 5 min).
    """
    try:
        result = auth.login(str(body.email), body.passphrase)
    except AccountLockedError as exc:
        raise HTTPException(status_code=423,
                            detail=f"Account locked until {exc.locked_until}")
    except AuthenticationError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Invalid email or passphrase")
    return LoginResponse(**result)


@router.post("/logout")
def logout(
    authorization: str | None = Header(default=None),
    auth: AuthService = Depends(get_auth),
):
    """Invalidate the current session token."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="UNAUTHENTICATED")
    token = authorization.removeprefix("Bearer ").strip()
    auth.logout(token)
    return {"message": "Logged out successfully"}
