"""
Tests for Feature 0.2 — User Identity Authentication.

Acceptance criteria (from spec):
  ✓  Register: hashes passphrase (never stores plaintext)
  ✓  Register: rejects duplicate email → UserAlreadyExistsError
  ✓  Register: rejects passphrase < 8 chars
  ✓  Register: rejects mismatched confirm
  ✓  Login: issues session token with 30-min TTL
  ✓  Login: rejects wrong passphrase (same error as unknown user)
  ✓  Login: 5 failed attempts → AccountLockedError for 5 min
  ✓  Login: lockout applied even on correct password during window
  ✓  Login: lockout expires after 5 min (fast-forward in test)
  ✓  Logout: invalidates the token
  ✓  verify_token: expired token → TokenExpiredError
  ✓  verify_token: missing token → TokenExpiredError
"""
import pathlib
import time
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from src.auth.service import (
    AccountLockedError,
    AuthService,
    AuthenticationError,
    TokenExpiredError,
    UserAlreadyExistsError,
    SESSION_TTL_MINUTES,
    MAX_FAILED_ATTEMPTS,
    LOCKOUT_MINUTES,
)


EMAIL    = "alice@example.com"
PASSPHRASE = "correct-horse-battery-staple"
CONFIRM  = "correct-horse-battery-staple"
WRONG    = "wrong-passphrase"


@pytest.fixture()
def auth(tmp_path: pathlib.Path) -> AuthService:
    """Fresh AuthService backed by a temp directory."""
    return AuthService(data_dir=str(tmp_path))


@pytest.fixture()
def registered_auth(auth: AuthService) -> AuthService:
    """AuthService with one user already registered."""
    auth.register(EMAIL, PASSPHRASE, CONFIRM)
    return auth


# ── Registration ───────────────────────────────────────────────────────────────

class TestRegister:
    def test_register_success(self, auth: AuthService) -> None:
        auth.register(EMAIL, PASSPHRASE, CONFIRM)  # must not raise

    def test_register_stores_hash_not_plaintext(self, registered_auth: AuthService) -> None:
        """Password must be stored as hash, never as plaintext."""
        record = registered_auth._users.get(EMAIL)
        assert record is not None
        assert PASSPHRASE not in str(record)
        assert "password_hash" in record

    def test_register_duplicate_email_raises(self, registered_auth: AuthService) -> None:
        with pytest.raises(UserAlreadyExistsError):
            registered_auth.register(EMAIL, PASSPHRASE, CONFIRM)

    def test_register_short_passphrase_raises(self, auth: AuthService) -> None:
        with pytest.raises(ValueError, match="8 characters"):
            auth.register(EMAIL, "short", "short")

    def test_register_mismatch_confirm_raises(self, auth: AuthService) -> None:
        with pytest.raises(ValueError, match="do not match"):
            auth.register(EMAIL, PASSPHRASE, "other-passphrase")

    def test_register_creates_user_record(self, registered_auth: AuthService) -> None:
        record = registered_auth._users.get(EMAIL)
        assert record["email"] == EMAIL
        assert record["failed_attempts"] == 0
        assert record["locked_until"] is None


# ── Login ──────────────────────────────────────────────────────────────────────

class TestLogin:
    def test_login_success_returns_token(self, registered_auth: AuthService) -> None:
        result = registered_auth.login(EMAIL, PASSPHRASE)
        assert "token" in result
        assert "expires_at" in result

    def test_token_format(self, registered_auth: AuthService) -> None:
        result = registered_auth.login(EMAIL, PASSPHRASE)
        assert result["token"].startswith("mv_")

    def test_wrong_passphrase_raises(self, registered_auth: AuthService) -> None:
        with pytest.raises(AuthenticationError):
            registered_auth.login(EMAIL, WRONG)

    def test_unknown_user_raises_same_error(self, auth: AuthService) -> None:
        """'user not found' and 'wrong password' must be indistinguishable."""
        with pytest.raises(AuthenticationError):
            auth.login("nonexistent@example.com", WRONG)

    def test_failed_attempts_incremented(self, registered_auth: AuthService) -> None:
        try:
            registered_auth.login(EMAIL, WRONG)
        except AuthenticationError:
            pass
        record = registered_auth._users.get(EMAIL)
        assert record["failed_attempts"] == 1

    def test_lockout_after_max_attempts(self, registered_auth: AuthService) -> None:
        """After MAX_FAILED_ATTEMPTS, account should be locked."""
        for _ in range(MAX_FAILED_ATTEMPTS):
            try:
                registered_auth.login(EMAIL, WRONG)
            except AuthenticationError:
                pass
        with pytest.raises(AccountLockedError):
            registered_auth.login(EMAIL, PASSPHRASE)  # correct but locked

    def test_lockout_applies_to_correct_password(self, registered_auth: AuthService) -> None:
        """Lockout must block even correct password during the window."""
        for _ in range(MAX_FAILED_ATTEMPTS):
            try:
                registered_auth.login(EMAIL, WRONG)
            except AuthenticationError:
                pass
        with pytest.raises(AccountLockedError):
            registered_auth.login(EMAIL, PASSPHRASE)

    def test_lockout_expires(self, registered_auth: AuthService) -> None:
        """After lockout window, login should succeed again."""
        for _ in range(MAX_FAILED_ATTEMPTS):
            try:
                registered_auth.login(EMAIL, WRONG)
            except AuthenticationError:
                pass

        # Fast-forward past the lockout window
        future = datetime.now(tz=timezone.utc) + timedelta(minutes=LOCKOUT_MINUTES + 1)
        with patch("src.auth.service._utcnow", return_value=future):
            result = registered_auth.login(EMAIL, PASSPHRASE)
        assert "token" in result

    def test_success_resets_failed_attempts(self, registered_auth: AuthService) -> None:
        try:
            registered_auth.login(EMAIL, WRONG)
        except AuthenticationError:
            pass
        registered_auth.login(EMAIL, PASSPHRASE)
        record = registered_auth._users.get(EMAIL)
        assert record["failed_attempts"] == 0

    def test_token_ttl_is_30_minutes(self, registered_auth: AuthService) -> None:
        result = registered_auth.login(EMAIL, PASSPHRASE)
        expires = datetime.fromisoformat(result["expires_at"])
        now = datetime.now(tz=timezone.utc)
        diff = expires - now
        # Allow 2 second tolerance
        assert abs(diff.total_seconds() - SESSION_TTL_MINUTES * 60) < 2


# ── Logout ─────────────────────────────────────────────────────────────────────

class TestLogout:
    def test_logout_invalidates_token(self, registered_auth: AuthService) -> None:
        result = registered_auth.login(EMAIL, PASSPHRASE)
        token = result["token"]
        registered_auth.logout(token)
        with pytest.raises(TokenExpiredError):
            registered_auth.verify_token(token)

    def test_logout_nonexistent_token_silent(self, registered_auth: AuthService) -> None:
        """Logging out an already-gone token must be a silent no-op."""
        registered_auth.logout("mv_nonexistenttoken")  # must not raise


# ── Token verification ─────────────────────────────────────────────────────────

class TestVerifyToken:
    def test_valid_token_returns_email(self, registered_auth: AuthService) -> None:
        result = registered_auth.login(EMAIL, PASSPHRASE)
        email = registered_auth.verify_token(result["token"])
        assert email == EMAIL

    def test_expired_token_raises(self, registered_auth: AuthService) -> None:
        result = registered_auth.login(EMAIL, PASSPHRASE)
        token = result["token"]
        past = datetime.now(tz=timezone.utc) - timedelta(minutes=SESSION_TTL_MINUTES + 1)
        with patch("src.auth.service._utcnow", return_value=past):
            registered_auth.login(EMAIL, PASSPHRASE)  # issue another token at fake time
        # Now verify with real time → expired
        future = datetime.now(tz=timezone.utc) + timedelta(minutes=SESSION_TTL_MINUTES + 1)
        with patch("src.auth.service._utcnow", return_value=future):
            with pytest.raises(TokenExpiredError):
                registered_auth.verify_token(token)

    def test_missing_token_raises(self, registered_auth: AuthService) -> None:
        with pytest.raises(TokenExpiredError):
            registered_auth.verify_token("")

    def test_unknown_token_raises(self, registered_auth: AuthService) -> None:
        with pytest.raises(TokenExpiredError):
            registered_auth.verify_token("mv_totallyfaketoken")
