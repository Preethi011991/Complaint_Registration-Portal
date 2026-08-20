"""Token lifecycle security: validation, identity extraction, revocation.

Token payloads must never contain a password, password hash, or email —
see the docstring in jwt_tokens.py for why. This module only ever reads
claims that are already safe to expose to the token holder.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Protocol

import jwt
import redis as redis_lib

from app.security.security_config import get_security_config
from app.security.security_errors import (
    ExpiredTokenError,
    InvalidTokenError,
    RevokedTokenError,
    WrongTokenTypeError,
)

_REVOKED_KEY_PREFIX = "revoked_session:"


@dataclass(frozen=True)
class TokenClaims:
    """Typed view of a validated token's claims.

    department_id is None for citizen tokens, which don't carry one.
    """

    user_id: str
    role: str
    session_id: str
    issued_at: int
    expires_at: int
    department_id: str | None = None


class RevocationStore(Protocol):
    """Interface for storing revoked session ids with an expiry.

    Kept small and swappable so tests can use an in-memory implementation
    instead of talking to a real Redis instance.
    """

    def set_with_ttl(self, key: str, value: str, ttl_seconds: int) -> None:
        ...

    def exists(self, key: str) -> bool:
        ...


class RedisRevocationStore:
    """Redis-backed RevocationStore."""

    def __init__(self, redis_url: str | None = None) -> None:
        url = redis_url or get_security_config().redis_url
        self._client = redis_lib.from_url(url)

    def set_with_ttl(self, key: str, value: str, ttl_seconds: int) -> None:
        if ttl_seconds > 0:
            self._client.set(key, value, ex=ttl_seconds)

    def exists(self, key: str) -> bool:
        return bool(self._client.exists(key))


class InMemoryRevocationStore:
    """In-memory RevocationStore for tests — no Redis required."""

    def __init__(self) -> None:
        self._store: dict[str, float] = {}

    def set_with_ttl(self, key: str, value: str, ttl_seconds: int) -> None:
        if ttl_seconds > 0:
            self._store[key] = time.time() + ttl_seconds

    def exists(self, key: str) -> bool:
        expires_at = self._store.get(key)
        if expires_at is None:
            return False
        if expires_at <= time.time():
            del self._store[key]
            return False
        return True


_default_store: RevocationStore | None = None


def _get_store() -> RevocationStore:
    global _default_store
    if _default_store is None:
        _default_store = RedisRevocationStore()
    return _default_store


def set_revocation_store(store: RevocationStore) -> None:
    """Override the module's revocation store (used by tests)."""
    global _default_store
    _default_store = store


def _revocation_key(session_id: str) -> str:
    return f"{_REVOKED_KEY_PREFIX}{session_id}"


def revoke_token(session_id: str, user_id: str) -> bool:
    """Revoke a session so its tokens are rejected on future validation.

    Stores the revoked session_id with a TTL matching the remaining
    lifetime of a token issued with the default expiry. In practice, the
    caller (e.g. a logout endpoint) should know the actual token's exp
    claim and can rely on validate_token consulting this store for as
    long as any token for this session could still be valid.

    Args:
        session_id: The session to revoke.
        user_id: The user the session belongs to (recorded for audit
            purposes; the revocation key itself is keyed on session_id).

    Returns:
        True once the revocation has been recorded.
    """
    config = get_security_config()
    ttl_seconds = config.access_token_expiry_minutes * 60
    _get_store().set_with_ttl(_revocation_key(session_id), user_id, ttl_seconds)
    return True


def is_token_revoked(session_id: str) -> bool:
    """Check whether a session has been revoked.

    Args:
        session_id: The session id to check.

    Returns:
        True if the session was revoked and the revocation entry has not
        yet expired.
    """
    return _get_store().exists(_revocation_key(session_id))


def _claims_from_payload(payload: dict) -> TokenClaims:
    return TokenClaims(
        user_id=payload["sub"],
        role=payload["role"],
        session_id=payload["session_id"],
        issued_at=payload["iat"],
        expires_at=payload["exp"],
        department_id=payload.get("department_id"),
    )


def validate_token(token: str, expected_user_type: str | None = None) -> TokenClaims:
    """Validate a JWT and return its claims.

    Checks are performed in order: signature validity, expiry, session
    revocation, then role match — so callers always get the most
    specific applicable error.

    Args:
        token: The encoded JWT string.
        expected_user_type: If given, the token's role must match this
            value exactly, or WrongTokenTypeError is raised.

    Returns:
        TokenClaims parsed from the token's payload.

    Raises:
        InvalidTokenError: If the signature or structure is invalid.
        ExpiredTokenError: If the token's exp claim has passed.
        RevokedTokenError: If the token's session has been revoked.
        WrongTokenTypeError: If expected_user_type is given and doesn't
            match the token's role.
    """
    config = get_security_config()

    try:
        payload = jwt.decode(
            token,
            config.jwt_secret,
            algorithms=[config.jwt_algorithm],
            options={"require": ["exp", "iat", "sub", "role", "session_id"]},
        )
    except jwt.ExpiredSignatureError as exc:
        raise ExpiredTokenError("Token has expired.") from exc
    except jwt.InvalidTokenError as exc:
        raise InvalidTokenError(f"Token is invalid: {exc}") from exc

    session_id = payload["session_id"]
    if is_token_revoked(session_id):
        raise RevokedTokenError(f"Session {session_id!r} has been revoked.")

    role = payload["role"]
    if expected_user_type is not None and role != expected_user_type:
        raise WrongTokenTypeError(
            f"Expected token role {expected_user_type!r}, got {role!r}."
        )

    return _claims_from_payload(payload)


def get_token_identity(validated_token: TokenClaims) -> TokenClaims:
    """Return the identity carried by an already-validated token.

    This is a passthrough that exists so callers have one clear place to
    get "who is this" from a token that has already gone through
    validate_token — it does not re-validate.

    Args:
        validated_token: A TokenClaims previously returned by
            validate_token.

    Returns:
        The same TokenClaims.
    """
    return validated_token
