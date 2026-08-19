"""Password hashing and verification (Argon2id).

No function in this file may log, print, or otherwise emit a plaintext
password, in any form (including exceptions or debug output).
"""

from __future__ import annotations

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError, VerificationError

_hasher = PasswordHasher()

_MIN_LENGTH = 8


def hash_password(plain_password: str) -> str:
    """Hash a plaintext password using Argon2id.

    Args:
        plain_password: The user's plaintext password.

    Returns:
        An encoded Argon2id hash string, safe to store in the database.
        The returned string embeds the algorithm parameters and a random
        salt, so it can be verified later without any extra state.
    """
    return _hasher.hash(plain_password)


def verify_password(plain_password: str, password_hash: str) -> bool:
    """Check a plaintext password attempt against a stored Argon2id hash.

    Uses argon2-cffi's own verify method, which performs a constant-time
    comparison internally, so this function is resistant to timing
    attacks. It never compares strings with `==`.

    Args:
        plain_password: The plaintext password supplied by the caller.
        password_hash: The stored Argon2id hash to check against.

    Returns:
        True if the password matches the hash. False if it does not
        match, or if password_hash is malformed/corrupted/not a valid
        Argon2 hash — this function never raises for those cases, so a
        corrupted database row cannot crash the login endpoint.
    """
    try:
        return _hasher.verify(password_hash, plain_password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def validate_password_strength(password: str) -> tuple[bool, list[str]]:
    """Check a candidate password against the portal's strength rules.

    Rules:
        - At least 8 characters long.
        - Contains at least one letter.
        - Contains at least one digit.

    Args:
        password: The candidate plaintext password to check.

    Returns:
        A tuple of (is_valid, failure_reasons). is_valid is True only if
        every rule passes. failure_reasons lists every rule that failed
        (not just the first), so the UI can show a complete list.
    """
    failure_reasons: list[str] = []

    if len(password) < _MIN_LENGTH:
        failure_reasons.append(f"Password must be at least {_MIN_LENGTH} characters long.")

    if not any(char.isalpha() for char in password):
        failure_reasons.append("Password must contain at least one letter.")

    if not any(char.isdigit() for char in password):
        failure_reasons.append("Password must contain at least one digit.")

    return (len(failure_reasons) == 0, failure_reasons)
