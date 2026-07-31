"""
Feature 0.2 — User Identity Authentication service.

Responsibilities:
  • register(): hash passphrase with Argon2id, persist user record
  • login():     verify hash, issue UUID session token (30-min TTL),
                 enforce 5-attempt lockout for 5 minutes
  • logout():    delete session token from store
  • verify_token(): look up session; raise if missing / expired

Security decisions:
  • Passwords hashed via argon2.PasswordHasher (OWASP-recommended defaults),
    NOT the low-level derive_key used for the vault KEK — separate concerns.
  • On wrong password we do NOT distinguish "wrong password" from "account
    doesn't exist" — both return the same error to the caller.
  • Lockout applies even to the correct password during the 5-minute window.
"""
import secrets
import uuid
from datetime import datetime, timedelta, timezone

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError

from src.storage.json_store import JsonStore

# Argon2id password hasher (separate from KDF used for vault DEK)
_ph = PasswordHasher()

# Session TTL and brute-force lockout constants (spec requirements)
SESSION_TTL_MINUTES   = 30
MAX_FAILED_ATTEMPTS   = 5
LOCKOUT_MINUTES       = 5


class AuthError(Exception):
    """Base class for auth errors."""


class UserAlreadyExistsError(AuthError):
    """Raised when registering with an email that is already taken."""


class AuthenticationError(AuthError):
    """
    Generic authentication failure. Deliberately does not distinguish
    between 'wrong password' and 'user not found' to prevent enumeration.
    """


class AccountLockedError(AuthError):
    """Raised when an account is temporarily locked after too many failures."""
    def __init__(self, locked_until: str):
        super().__init__(f"Account locked until {locked_until}")
        self.locked_until = locked_until


class TokenExpiredError(AuthError):
    """Raised when a session token has expired or does not exist."""


def _utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.isoformat()


def _from_iso(s: str) -> datetime:
    return datetime.fromisoformat(s)


class AuthService:
    def __init__(self, data_dir: str = "data") -> None:
        self._users    = JsonStore(f"{data_dir}/users")
        self._sessions = JsonStore(f"{data_dir}/sessions")

    # ── Registration ──────────────────────────────────────────────────────────

    def register(self, email: str, passphrase: str, confirm: str) -> None:
        """
        Register a new user.
        Raises UserAlreadyExistsError if the email is taken.
        Raises ValueError for weak passphrase or mismatched confirm.
        """
        if passphrase != confirm:
            raise ValueError("Passphrases do not match")
        if len(passphrase) < 8:
            raise ValueError("Passphrase must be at least 8 characters")
        if self._users.exists(email):
            raise UserAlreadyExistsError(f"Email already registered: {email}")

        self._users.put(email, data={
            "email":           email,
            "password_hash":   _ph.hash(passphrase),
            "failed_attempts": 0,
            "locked_until":    None,   # ISO string or null
            "created_at":      _iso(_utcnow()),
        })

    # ── Login ─────────────────────────────────────────────────────────────────

    def login(self, email: str, passphrase: str) -> dict:
        """
        Verify credentials and issue a session token.

        Returns: {"token": str, "expires_at": ISO-string}

        Raises:
          AccountLockedError       — account is in 5-minute lockout
          AuthenticationError      — wrong password or user not found
        """
        user = self._users.get(email)

        # --- lockout check (must run before password check) ---
        if user and user.get("locked_until"):
            locked_until = _from_iso(user["locked_until"])
            if _utcnow() < locked_until:
                raise AccountLockedError(user["locked_until"])
            else:
                # Lockout expired — reset counter
                user["failed_attempts"] = 0
                user["locked_until"]    = None
                self._users.put(email, data=user)

        # --- password verification ---
        valid = False
        if user:
            try:
                _ph.verify(user["password_hash"], passphrase)
                valid = True
            except (VerifyMismatchError, VerificationError, InvalidHashError):
                valid = False

        if not valid:
            # Increment failure counter (or silently ignore if user not found
            # — do not reveal whether the account exists)
            if user:
                user["failed_attempts"] = user.get("failed_attempts", 0) + 1
                if user["failed_attempts"] >= MAX_FAILED_ATTEMPTS:
                    user["locked_until"] = _iso(
                        _utcnow() + timedelta(minutes=LOCKOUT_MINUTES)
                    )
                self._users.put(email, data=user)
            raise AuthenticationError("Invalid email or passphrase")

        # --- success: reset failure counter, issue token ---
        user["failed_attempts"] = 0
        user["locked_until"]    = None
        self._users.put(email, data=user)

        token      = f"mv_{uuid.uuid4().hex}"
        expires_at = _utcnow() + timedelta(minutes=SESSION_TTL_MINUTES)

        self._sessions.put(token, data={
            "email":      email,
            "expires_at": _iso(expires_at),
        })

        return {"token": token, "expires_at": _iso(expires_at)}

    # ── Logout ────────────────────────────────────────────────────────────────

    def logout(self, token: str) -> None:
        """Delete the session token. Silent no-op if already gone."""
        self._sessions.delete(token)

    # ── Token verification ────────────────────────────────────────────────────

    def verify_token(self, token: str) -> str:
        """
        Verify a session token and return the owner's email.
        Raises TokenExpiredError if token is missing or expired.
        """
        if not token:
            raise TokenExpiredError("No token provided")

        session = self._sessions.get(token)
        if not session:
            raise TokenExpiredError("Token not found or already expired")

        if _utcnow() > _from_iso(session["expires_at"]):
            self._sessions.delete(token)
            raise TokenExpiredError("Token expired — please log in again")

        return session["email"]
