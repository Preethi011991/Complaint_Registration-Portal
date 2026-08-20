"""JWT issuance (access/refresh tokens).

Token payloads must never contain a password, password hash, or email.
JWTs are only signed, not encrypted — anyone holding a token can decode
and read its payload (e.g. at jwt.io) without ever needing the signing
key. Putting sensitive data in a claim would expose it to anyone who
intercepts or is handed a token, and would leak it into logs, browser
storage, and any proxy/CDN that happens to inspect requests.
"""

from __future__ import annotations

import time

import jwt

from app.security.security_config import get_security_config

_CITIZEN_ROLE = "CITIZEN"


def _encode(claims: dict) -> str:
    config = get_security_config()
    return jwt.encode(claims, config.jwt_secret, algorithm=config.jwt_algorithm)


def _issued_and_expiry(expiry_minutes: int | None) -> tuple[int, int]:
    config = get_security_config()
    minutes = expiry_minutes if expiry_minutes is not None else config.access_token_expiry_minutes
    issued_at = int(time.time())
    expires_at = issued_at + (minutes * 60)
    return issued_at, expires_at


def generate_citizen_token(
    user_id: str, session_id: str, expiry_minutes: int | None = None
) -> str:
    """Generate a signed JWT for a citizen user.

    Args:
        user_id: The citizen's unique identifier. Becomes the `sub` claim.
        session_id: Identifier for this login session, used later to
            support revocation (e.g. on logout).
        expiry_minutes: Optional override for token lifetime. Defaults to
            the configured access token expiry.

    Returns:
        An encoded JWT string with claims: sub, role="CITIZEN",
        session_id, iat, exp.
    """
    issued_at, expires_at = _issued_and_expiry(expiry_minutes)
    claims = {
        "sub": user_id,
        "role": _CITIZEN_ROLE,
        "session_id": session_id,
        "iat": issued_at,
        "exp": expires_at,
    }
    return _encode(claims)


def generate_employee_token(
    employee_id: str,
    role: str,
    department_id: str,
    session_id: str,
    expiry_minutes: int | None = None,
) -> str:
    """Generate a signed JWT for an employee user.

    Args:
        employee_id: The employee's unique identifier. Becomes the `sub`
            claim.
        role: The employee's role (e.g. "ADMIN", "AGENT"), used later by
            RBAC checks.
        department_id: The department the employee belongs to.
        session_id: Identifier for this login session, used later to
            support revocation (e.g. on logout).
        expiry_minutes: Optional override for token lifetime. Defaults to
            the configured access token expiry.

    Returns:
        An encoded JWT string with claims: sub, role, department_id,
        session_id, iat, exp.
    """
    issued_at, expires_at = _issued_and_expiry(expiry_minutes)
    claims = {
        "sub": employee_id,
        "role": role,
        "department_id": department_id,
        "session_id": session_id,
        "iat": issued_at,
        "exp": expires_at,
    }
    return _encode(claims)


def initialize_jwt_token(
    user_id: str, role: str, session_id: str, expiry_minutes: int | None = None
) -> str:
    """Generate a signed JWT, dispatching to the citizen or employee shape.

    Args:
        user_id: The user's unique identifier (citizen user_id or
            employee_id).
        role: The user's role. "CITIZEN" produces a citizen token; any
            other value is treated as an employee role.
        session_id: Identifier for this login session.
        expiry_minutes: Optional override for token lifetime.

    Returns:
        An encoded JWT string, shaped per generate_citizen_token or
        generate_employee_token depending on role.

    Raises:
        ValueError: If role is an employee role but no department_id can
            be determined (employee tokens require one; use
            generate_employee_token directly when a department_id is
            available).
    """
    if role == _CITIZEN_ROLE:
        return generate_citizen_token(user_id, session_id, expiry_minutes)

    raise ValueError(
        "initialize_jwt_token cannot build an employee token without a "
        "department_id — call generate_employee_token directly for "
        f"role={role!r}."
    )
