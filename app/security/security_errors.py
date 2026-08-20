"""Security-layer exception types."""


class SecurityConfigError(Exception):
    """Raised when required security configuration is missing or invalid."""


class SecurityError(Exception):
    """Base type for all token/auth security failures."""


class InvalidTokenError(SecurityError):
    """Raised when a token's signature or structure is invalid."""


class ExpiredTokenError(SecurityError):
    """Raised when a token's expiry (exp claim) has passed."""


class RevokedTokenError(SecurityError):
    """Raised when a token's session has been explicitly revoked."""


class WrongTokenTypeError(SecurityError):
    """Raised when a token's role does not match the expected user type."""


class UnknownRoleError(SecurityError):
    """Raised when a role has no entry in the RBAC permission mapping."""
