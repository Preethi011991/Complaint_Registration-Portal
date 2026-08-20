"""Security configuration loaded from environment variables.

Non-secret values (algorithm, expiry) get safe defaults. Secrets (like the
JWT signing key) are never defaulted — a missing secret must fail startup
loudly, not silently fall back to an insecure or guessable value.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from app.security.security_errors import SecurityConfigError

_DEFAULT_JWT_ALGORITHM = "HS256"
_DEFAULT_ACCESS_TOKEN_EXPIRY_MINUTES = 15
_DEFAULT_REDIS_URL = "redis://localhost:6379/0"
_DEFAULT_ENVIRONMENT = "development"


@dataclass(frozen=True)
class SecurityConfig:
    """Immutable snapshot of the security layer's configuration."""

    jwt_secret: str
    jwt_algorithm: str
    access_token_expiry_minutes: int
    redis_url: str
    environment: str


def get_secret(secret_name: str) -> str:
    """Fetch a named secret.

    Currently reads from environment variables. Callers should treat this
    as the single point of access for secrets, so the underlying source
    can later be swapped for a secret store (e.g. AWS Secrets Manager or
    HashiCorp Vault) without any caller needing to change.

    Args:
        secret_name: The name of the secret to fetch (currently the
            environment variable name).

    Returns:
        The secret's value.

    Raises:
        SecurityConfigError: If the secret is not set.
    """
    value = os.environ.get(secret_name)
    if not value:
        raise SecurityConfigError(
            f"Required secret '{secret_name}' is not set. "
            "Set it via an environment variable (see .env.example)."
        )
    return value


def get_security_config(environment: str | None = None) -> SecurityConfig:
    """Build the security layer's configuration from environment variables.

    Args:
        environment: Optional override for the running environment name
            (e.g. "development", "staging", "production"). If not given,
            falls back to the APP_ENV environment variable, then to a
            safe default.

    Returns:
        A populated, immutable SecurityConfig.

    Raises:
        SecurityConfigError: If JWT_SECRET_KEY is not set. There is no
            default for it — see the module docstring and get_secret.
    """
    jwt_secret = get_secret("JWT_SECRET_KEY")

    jwt_algorithm = os.environ.get("JWT_ALGORITHM", _DEFAULT_JWT_ALGORITHM)

    raw_expiry = os.environ.get(
        "JWT_ACCESS_TOKEN_EXPIRE_MINUTES", str(_DEFAULT_ACCESS_TOKEN_EXPIRY_MINUTES)
    )
    try:
        access_token_expiry_minutes = int(raw_expiry)
    except ValueError as exc:
        raise SecurityConfigError(
            f"JWT_ACCESS_TOKEN_EXPIRE_MINUTES must be an integer, got: {raw_expiry!r}"
        ) from exc

    redis_url = os.environ.get("REDIS_URL", _DEFAULT_REDIS_URL)

    resolved_environment = environment or os.environ.get("APP_ENV", _DEFAULT_ENVIRONMENT)

    return SecurityConfig(
        jwt_secret=jwt_secret,
        jwt_algorithm=jwt_algorithm,
        access_token_expiry_minutes=access_token_expiry_minutes,
        redis_url=redis_url,
        environment=resolved_environment,
    )
