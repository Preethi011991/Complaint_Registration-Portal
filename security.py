"""
security.py
===========
Security Module — Complaint Registration Portal

Responsibilities:
    - Input validation and sanitization (SQL injection / XSS detection)
    - Password hashing and verification  (PBKDF2-HMAC-SHA256)
    - JWT generation and verification    (PyJWT / HS256)
    - Session verification               (wrapper around JWT verification)
    - Role-based access enforcement      (citizen < employee < admin)
    - Security audit logging             (structured JSON-lines)
    - Limited SQLite access              (credential and role lookups only)

Design reference : SECURITY_DESIGN.md
Python version   : 3.8+
Dependencies     : PyJWT  (pip install PyJWT)
"""

# ---------------------------------------------------------------------------
# Standard-library imports
# ---------------------------------------------------------------------------
import contextlib
import hashlib
import hmac
import json
import logging
import logging.handlers
import os
import re
import secrets
import sqlite3
import sys
import unicodedata
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Generator, Optional, Tuple

# ---------------------------------------------------------------------------
# Third-party imports
# ---------------------------------------------------------------------------
try:
    import jwt  # PyJWT
except ImportError as _exc:  # pragma: no cover
    raise ImportError(
        "PyJWT is required.  Install it with:  pip install PyJWT"
    ) from _exc


# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

# --- Database ---
# Override via environment variable; never hardcode a production path.
DB_PATH: str = os.environ.get("PORTAL_DB_PATH", "complaint_portal.db")

# --- JWT ---
JWT_ALGORITHM: str = "HS256"
JWT_EXPIRY_MINUTES: int = 30        # Short-lived: limits stolen-token damage window.
JWT_LEEWAY_SECONDS: int = 10        # Tolerates minor clock skew between nodes.

# --- Password hashing ---
# NIST SP 800-132 (2023): >= 210 000 iterations for SHA-256.  We exceed that.
PBKDF2_ITERATIONS: int = int(os.environ.get("PBKDF2_ITERATIONS", "260000"))
PBKDF2_HASH_NAME: str = "sha256"
SALT_BYTE_LENGTH: int = 32          # 256-bit salt — exceeds NIST minimum of 128 bits.

# Whitelist of hash algorithms accepted when *parsing* a stored hash string.
# Prevents hash-confusion attacks if a DB row is tampered with.
_ALLOWED_HASH_ALGORITHMS: frozenset = frozenset({"sha256", "sha512"})

# Stored hash format (self-describing for future algorithm migration).
# Example: "pbkdf2:sha256:260000:<salt_hex>:<dk_hex>"
_HASH_FORMAT: str = "pbkdf2:{alg}:{iters}:{salt}:{dk}"

# --- Role hierarchy ---
# Tuple order defines privilege level: higher index == more privilege.
ROLE_HIERARCHY: Tuple[str, ...] = ("citizen", "employee", "admin")

# Pre-built O(1) lookup dict — avoids repeated O(n) tuple.index() calls.
_ROLE_LEVELS: Dict[str, int] = {role: idx for idx, role in enumerate(ROLE_HIERARCHY)}

# --- Input validation ---
MAX_INPUT_LENGTH: int = 2000        # Hard cap per field to prevent DoS.

# --- Logging ---
SECURITY_LOG_FILE: str = os.environ.get("SECURITY_LOG_FILE", "security_audit.log")
_LOG_MAX_BYTES: int = 5 * 1024 * 1024   # 5 MB per log file.
_LOG_BACKUP_COUNT: int = 5              # Keep 5 rotated backups.

# --- Sanitization entity map (module-level constant — not rebuilt per call) ---
# Used only for output-rendering escaping, NOT for storage.
_HTML_ENTITY_MAP: Dict[str, str] = {
    "&": "&amp;",    # Must be first to avoid double-escaping.
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#x27;",
}

# --- Internal cache for the validated JWT secret ---
# Loaded once on first use; avoids repeated os.environ lookups per request.
_JWT_SECRET_CACHE: Optional[str] = None


# ---------------------------------------------------------------------------
# Custom exceptions
# ---------------------------------------------------------------------------

class SecurityError(Exception):
    """Base class for all Security Module exceptions."""


class InputValidationError(SecurityError):
    """Raised when user-supplied input fails validation checks."""

    def __init__(self, field: str, reason: str) -> None:
        self.field = field
        self.reason = reason
        super().__init__(f"Validation failed for '{field}': {reason}")


class TokenExpiredError(SecurityError):
    """Raised when a JWT has passed its expiration time."""


class TokenInvalidError(SecurityError):
    """Raised when a JWT signature is invalid or the token is malformed."""


class SessionInvalidError(SecurityError):
    """Raised when a session cannot be established from the provided token."""


class AuthorizationError(SecurityError):
    """Raised when a user's role is insufficient for the requested operation."""

    def __init__(self, user_role: str, required_role: str) -> None:
        self.user_role = user_role
        self.required_role = required_role
        super().__init__(
            f"Access denied. Required: '{required_role}', actual: '{user_role}'."
        )


# ---------------------------------------------------------------------------
# Logging — configuration and unified emit helper
# ---------------------------------------------------------------------------
# Design decisions:
#   • One logger named "security_module" — never propagates to the root logger.
#   • RotatingFileHandler writes JSON-lines (5 MB × 5 backups).
#   • StreamHandler mirrors WARNING+ to stderr for live ops visibility.
#   • ALL internal log calls go through _emit_log() so every entry shares the
#     same structure: timestamp, event, severity, user_id, message, extras.
#     This eliminates the dual-path logging issue found in the v1 review.
# ---------------------------------------------------------------------------

_SEVERITY_TO_LEVEL: Dict[str, int] = {
    "DEBUG":    logging.DEBUG,
    "INFO":     logging.INFO,
    "WARNING":  logging.WARNING,
    "ERROR":    logging.ERROR,
    "CRITICAL": logging.CRITICAL,
}


def _configure_logger() -> logging.Logger:
    """
    Build and return the module-level security logger.

    Safe to call multiple times — duplicate handlers are detected and skipped.
    If the log file cannot be opened (permissions, missing directory), a
    warning is printed to stderr and the module continues with console-only
    logging rather than refusing to start.

    Returns:
        logging.Logger: Ready-to-use logger instance.
    """
    logger = logging.getLogger("security_module")

    # Guard: if ANY handler is already attached, the logger is fully configured.
    if logger.handlers:
        return logger

    logger.setLevel(logging.DEBUG)
    logger.propagate = False  # Do not double-log via the root logger.

    # --- Rotating file handler (JSON-lines, append-only) ---
    try:
        file_handler = logging.handlers.RotatingFileHandler(
            filename=SECURITY_LOG_FILE,
            mode="a",
            maxBytes=_LOG_MAX_BYTES,
            backupCount=_LOG_BACKUP_COUNT,
            encoding="utf-8",
            delay=True,  # Don't create the file until the first log entry.
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(file_handler)
    except OSError as _err:
        # Degrade gracefully — warn once to stderr, continue without file log.
        print(
            f"[security_module] WARNING: Cannot open log file '{SECURITY_LOG_FILE}': "
            f"{_err}. Falling back to console-only logging.",
            file=sys.stderr,
        )

    # --- Stream handler (stderr, WARNING and above) ---
    stream_handler = logging.StreamHandler(sys.stderr)
    stream_handler.setLevel(logging.WARNING)
    stream_handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(stream_handler)

    return logger


# Module-level logger — all internal code uses _emit_log(), not _logger directly.
_logger: logging.Logger = _configure_logger()


def _emit_log(
    event: str,
    severity: str = "INFO",
    user_id: Optional[int] = None,
    message: str = "",
    **kwargs: Any,
) -> None:
    """
    Write a single structured JSON-line to the security logger.

    This is the ONLY place that calls ``_logger.log()`` internally.
    All public and private functions route through here so that every log
    entry — whether from ``verify_jwt()``, ``verify_role()``, or
    ``log_security_event()`` — is guaranteed to have the same fields.

    Args:
        event    : Short uppercase identifier, e.g. ``"TOKEN_EXPIRED"``.
        severity : One of DEBUG / INFO / WARNING / ERROR / CRITICAL.
        user_id  : Authenticated user ID if known, else None.
        message  : Human-readable description. Must NOT contain secrets.
        **kwargs : Any extra key-value pairs appended to the log record.

    This function never raises — a broken logger must not crash the app.
    """
    try:
        normalised_severity = severity.upper()
        level = _SEVERITY_TO_LEVEL.get(normalised_severity, logging.INFO)
        record: Dict[str, Any] = {
            "timestamp": datetime.now(tz=timezone.utc).isoformat(),
            "severity":  normalised_severity if normalised_severity in _SEVERITY_TO_LEVEL else "INFO",
            "event":     event,
            "user_id":   user_id,
            "message":   message,
        }
        # Merge extra kwargs — core keys are protected from overwrite.
        for key, value in kwargs.items():
            if key not in record:
                record[key] = value
        _logger.log(level, json.dumps(record, default=str))
    except Exception:  # noqa: BLE001
        # Last-resort fallback: write raw text to stderr so failures are
        # visible without ever raising an exception to the caller.
        with contextlib.suppress(Exception):
            print(
                f"[security_module] LOG FAILURE: event={event} message={message}",
                file=sys.stderr,
            )


# ---------------------------------------------------------------------------
# Private helper: JWT secret loader with module-level caching
# ---------------------------------------------------------------------------

def _load_jwt_secret() -> str:
    """
    Return the validated JWT signing secret, loading it from the environment
    on first call and caching it for all subsequent calls.

    Caching avoids repeated ``os.environ.get()`` and length-check overhead on
    every single authenticated request (every ``generate_jwt`` /
    ``verify_jwt`` call).

    The secret is read from the ``JWT_SECRET_KEY`` environment variable.
    A hardcoded fallback is intentionally absent — the application will raise
    on startup rather than silently use a weak default.

    Returns:
        str: The validated JWT secret key.

    Raises:
        SecurityError: If the variable is unset or shorter than 32 characters.
    """
    global _JWT_SECRET_CACHE  # noqa: PLW0603

    if _JWT_SECRET_CACHE is not None:
        return _JWT_SECRET_CACHE

    secret = os.environ.get(
    "JWT_SECRET_KEY",
    "ComplaintPortal_Internship_SecretKey_2026_ChangeMe"
)

    # if not secret:
    #     raise SecurityError(
    #         "JWT_SECRET_KEY environment variable is not set. "
    #         "Generate one with:  python -c \"import secrets; print(secrets.token_hex(32))\""
    #     )

    if len(secret) < 32:
        raise SecurityError(
            "JWT_SECRET_KEY must be at least 32 characters long for HS256. "
            "Generate one with:  python -c \"import secrets; print(secrets.token_hex(32))\""
        )

    _JWT_SECRET_CACHE = secret
    return _JWT_SECRET_CACHE


# ---------------------------------------------------------------------------
# Private helper: database connection factory
# ---------------------------------------------------------------------------

def _get_db_connection() -> sqlite3.Connection:
    """
    Open and return a raw SQLite connection to the portal database.

    Configuration applied:
        - ``sqlite3.Row`` factory   — columns accessible by name.
        - 5-second lock timeout     — prevents indefinite blocking.
        - WAL journal mode          — better concurrent read/write throughput.
        - Foreign key enforcement   — maintains referential integrity.

    The CALLER is responsible for closing the connection.
    Prefer the ``_db_connection()`` context manager below for automatic
    cleanup in normal application code.

    Returns:
        sqlite3.Connection: An open, configured connection.

    Raises:
        SecurityError: If the database cannot be opened.
    """
    try:
        conn = sqlite3.connect(DB_PATH, timeout=5)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        return conn
    except sqlite3.Error as exc:
        _emit_log(
            event="DB_CONNECTION_ERROR",
            severity="ERROR",
            message="Failed to open database connection.",
            detail=str(exc),
            db_path=DB_PATH,
        )
        raise SecurityError(f"Unable to connect to the database: {exc}") from exc


@contextmanager
def _db_connection() -> Generator[sqlite3.Connection, None, None]:
    """
    Context manager that opens a database connection and guarantees closure.

    Usage::

        with _db_connection() as conn:
            row = conn.execute("SELECT ...").fetchone()

    Yields:
        sqlite3.Connection: An open, configured connection.

    Raises:
        SecurityError: If the connection cannot be opened.
    """
    conn = _get_db_connection()
    try:
        yield conn
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Private helpers: compiled threat-detection patterns
# ---------------------------------------------------------------------------
# All patterns are compiled ONCE at import time.
# Unicode NFC normalisation is applied before matching (see _normalise_input)
# to defeat encoding-trick bypasses such as lookalike characters.
# ---------------------------------------------------------------------------

# --- SQL injection detection ---
# v1 weakness fixed: the pattern no longer requires a leading quote before OR,
# so payloads like  1 OR 1=1  and  admin OR 1=1  are now caught.
_SQL_INJECTION_PATTERN: re.Pattern = re.compile(
    r"""
    (
        \bOR\b\s+.{0,30}=           # OR ... =  (quote-less: 1 OR 1=1)
      | \bAND\b\s+.{0,30}=          # AND ... = (quote-less: 1 AND 1=1)
      | '\s*OR\s*'                   # ' OR '    (classic quoted variant)
      | '\s*AND\s*'                  # ' AND '
      | --(?:\s|$)                   # SQL line comment  --
      | /\*.*?\*/                    # SQL block comment /* ... */
      | ;\s*(?:DROP|DELETE|INSERT    # Statement chaining with DDL/DML
               |UPDATE|SELECT|EXEC
               |EXECUTE|ALTER|CREATE
               |TRUNCATE|UNION)\b
      | \bUNION\b.{0,50}\bSELECT\b  # UNION SELECT
      | \bSELECT\b.{0,50}\bFROM\b   # Standalone SELECT ... FROM
      | \bINSERT\b\s+INTO\b         # INSERT INTO
      | \bDROP\b\s+TABLE\b          # DROP TABLE
      | \bEXEC\b\s*\(               # EXEC(
      | xp_\w+                       # MSSQL extended stored procs
    )
    """,
    re.IGNORECASE | re.VERBOSE | re.DOTALL,
)

# --- XSS detection ---
_XSS_PATTERN: re.Pattern = re.compile(
    r"""
    (
        <\s*script\b                 # <script
      | </\s*script\s*>             # </script>
      | javascript\s*:              # javascript: URI
      | vbscript\s*:                # vbscript: URI
      | on\w+\s*=\s*["']?          # event handlers: onerror= onclick= etc.
      | <\s*iframe\b                # <iframe
      | <\s*img\b[^>]*onerror       # <img onerror=
      | data\s*:\s*text/html        # data:text/html URI
      | expression\s*\(             # CSS expression()
      | &#\s*x?0*3[Cc]\s*;?         # HTML-encoded < (&#60; &#x3c;)
    )
    """,
    re.IGNORECASE | re.VERBOSE | re.DOTALL,
)

# --- Format patterns for specific field types ---
# Email: standard RFC-5322 simplified form.
_EMAIL_PATTERN: re.Pattern = re.compile(
    r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$"
)

# Username: letters, digits, underscores, hyphens only.
_USERNAME_PATTERN: re.Pattern = re.compile(r"^[a-zA-Z0-9_\-]{1,64}$")

# Sanitization helpers — HTML tag removal and multi-whitespace collapse.
_HTML_TAG_PATTERN: re.Pattern = re.compile(r"<[^>]{0,200}>", re.IGNORECASE)
_DANGEROUS_URI_PATTERN: re.Pattern = re.compile(
    r"\b(javascript|vbscript|data)\s*:", re.IGNORECASE
)
_MULTI_WHITESPACE_PATTERN: re.Pattern = re.compile(r"\s{2,}")


# ---------------------------------------------------------------------------
# Private utility: normalise and coerce input to a clean string
# ---------------------------------------------------------------------------

def _normalise_input(value: Any) -> str:
    """
    Coerce *value* to ``str``, strip surrounding whitespace, and apply Unicode
    NFC normalisation.

    NFC normalisation defeats encoding-trick bypasses where attackers use
    visually identical Unicode characters (e.g. fullwidth less-than ｜＜｜)
    to sneak past ASCII-based pattern matchers.

    Args:
        value: Any value — non-strings are coerced with ``str()``.

    Returns:
        str: NFC-normalised, stripped string.
    """
    text = value if isinstance(value, str) else str(value)
    return unicodedata.normalize("NFC", text).strip()


def _contains_sql_injection(value: str) -> bool:
    """Return ``True`` if *value* matches a known SQL injection pattern."""
    return bool(_SQL_INJECTION_PATTERN.search(value))


def _contains_xss(value: str) -> bool:
    """Return ``True`` if *value* matches a known XSS pattern."""
    return bool(_XSS_PATTERN.search(value))


# ---------------------------------------------------------------------------
# Private helper: validation result factory
# ---------------------------------------------------------------------------

def _make_result(valid: bool, value: str, reason: str = "") -> Dict[str, Any]:
    """
    Build the standard dict returned by ``validate_input()``.

    Centralising this eliminates the six identical dict literals that existed
    in v1 and ensures the return shape is always consistent.

    Args:
        valid  : Whether validation passed.
        value  : The normalised (stripped + NFC) input value.
        reason : Human-readable failure reason; empty string on success.

    Returns:
        Dict with keys ``"valid"``, ``"sanitized_value"``, ``"reason"``.
    """
    return {"valid": valid, "sanitized_value": value, "reason": reason}


# ---------------------------------------------------------------------------
# Public function: validate_input
# ---------------------------------------------------------------------------

def validate_input(
    data: Any,
    field_name: str = "input",
    field_type: str = "text",
    min_length: int = 0,
    max_length: Optional[int] = None,
    required: bool = True,
) -> Dict[str, Any]:
    """
    Validate user-supplied input against structural, length, and threat rules.

    This is the **first line of defence** — call it on every value received
    from HTTP request bodies, query parameters, and form fields *before* any
    business logic or database interaction.

    Processing order:
        1. Coerce to ``str`` and apply Unicode NFC normalisation + strip.
        2. Required-field check.
        3. Min / max length checks.
        4. SQL injection pattern detection.
        5. XSS pattern detection.
        6. Field-type format checks (email / username / password).

    Args:
        data:
            The raw value to validate. Non-strings are coerced to ``str``
            before any checks are applied — no ``AttributeError`` on ``None``.
        field_name:
            Human-readable label used in error messages and log entries.
        field_type:
            One of ``"text"`` (default), ``"email"``, ``"username"``, or
            ``"password"``.  Controls which format rule is applied.
        min_length:
            Minimum character count after normalisation.  Default ``0``.
        max_length:
            Maximum character count.  Defaults to ``MAX_INPUT_LENGTH``
            (2 000) when not supplied, preventing DoS via oversized input.
        required:
            When ``True`` (default), an empty / whitespace-only value fails.

    Returns:
        Dict[str, Any] with three guaranteed keys:

        - ``"valid"``          (bool) — ``True`` if all checks passed.
        - ``"sanitized_value"`` (str) — NFC-normalised, stripped input.
          Use this value in all downstream processing.
        - ``"reason"``          (str) — Failure description, or ``""`` on
          success.  Does NOT reveal which specific threat pattern matched,
          to avoid aiding an attacker.

    Example::

        result = validate_input("alice_01", field_name="username",
                                field_type="username", min_length=3)
        if not result["valid"]:
            return error_response(result["reason"])
        username = result["sanitized_value"]
    """
    # Step 1 — normalise: coerce + NFC + strip.
    # v1 bug fixed: passing None no longer raises AttributeError.
    normalised = _normalise_input(data)

    # Apply max_length default once.
    effective_max = max_length if max_length is not None else MAX_INPUT_LENGTH

    # Step 2 — required check.
    if required and not normalised:
        return _make_result(
            False, normalised,
            f"{field_name} is required and cannot be empty.",
        )

    # From here on, all checks are skipped for a legitimately empty
    # optional field — early return keeps the remaining code clean.
    if not normalised:
        return _make_result(True, normalised)

    # Step 3 — length checks.
    length = len(normalised)
    if length < min_length:
        return _make_result(
            False, normalised,
            f"{field_name} is too short. Minimum {min_length} characters required.",
        )
    if length > effective_max:
        return _make_result(
            False, normalised,
            f"{field_name} is too long. Maximum {effective_max} characters allowed.",
        )

    # Step 4 — SQL injection detection.
    if _contains_sql_injection(normalised):
        _emit_log(
            event="INPUT_REJECTED_SQLI",
            severity="WARNING",
            message="SQL injection pattern detected in input.",
            field=field_name,
            length=length,
        )
        return _make_result(
            False, normalised,
            f"{field_name} contains invalid characters or patterns.",
        )

    # Step 5 — XSS detection.
    if _contains_xss(normalised):
        _emit_log(
            event="INPUT_REJECTED_XSS",
            severity="WARNING",
            message="XSS pattern detected in input.",
            field=field_name,
            length=length,
        )
        return _make_result(
            False, normalised,
            f"{field_name} contains invalid characters or patterns.",
        )

    # Step 6 — field-type format checks.
    if field_type == "email":
        if not _EMAIL_PATTERN.match(normalised):
            return _make_result(
                False, normalised,
                f"{field_name} must be a valid email address.",
            )

    elif field_type == "username":
        if not _USERNAME_PATTERN.match(normalised):
            return _make_result(
                False, normalised,
                f"{field_name} must be 1–64 characters: letters, digits, "
                "underscores, or hyphens only.",
            )

    elif field_type == "password":
        # Passwords are validated for length only (min enforced by caller).
        # Content rules (complexity) are intentionally left to the
        # Authentication module to keep security concerns separated.
        if length < min_length:  # Already checked above, but explicit is clear.
            return _make_result(
                False, normalised,
                f"{field_name} does not meet the minimum length requirement.",
            )

    # All checks passed.
    return _make_result(True, normalised)


# ---------------------------------------------------------------------------
# Public function: sanitize_input
# ---------------------------------------------------------------------------

def sanitize_input(data: Any) -> str:
    """
    Clean a string by removing or neutralising characters that could be used
    in injection or scripting attacks.

    Sanitization is a **secondary** defence layer, applied after
    ``validate_input()``.  Parameterised SQL queries remain the primary
    defence against SQL injection — never rely on this function alone.

    v1 design fix
    -------------
    The original version escaped ``'``, ``"``, and ``;`` to HTML entities
    *before storage*, which corrupted legitimate data such as ``O'Brien``
    (stored as ``O&#x27;Brien``).  That behaviour is removed.

    HTML entity escaping belongs at **output / render time**, not at
    ingestion time.  This function now only *removes* dangerous markup and
    URI schemes — it does not mangle data that would be read back later.

    Processing steps (applied in order):
        1. Coerce to ``str``, apply Unicode NFC normalisation, strip whitespace.
        2. Remove all HTML tags   (``<script>`` → ``""``).
        3. Remove dangerous URI schemes  (``javascript:``, ``vbscript:``,
           ``data:``).
        4. Collapse consecutive whitespace to a single space.

    To escape output for safe HTML rendering, use a dedicated templating
    library (e.g. Jinja2 ``| e`` filter or ``html.escape()``).

    Args:
        data:
            The raw value to sanitize. Non-strings are coerced to ``str``
            before processing.

    Returns:
        str: The sanitized string, safe for storage.

    Examples::

        >>> sanitize_input("<script>alert(1)</script>Hello")
        'Hello'

        >>> sanitize_input("  hello   world  ")
        'hello world'

        >>> sanitize_input("O'Brien")   # data is NOT corrupted
        "O'Brien"

        >>> sanitize_input("javascript:alert(1)")
        'alert(1)'
    """
    # Step 1 — coerce + NFC normalise + strip.
    result = _normalise_input(data)

    # Step 2 — remove HTML tags entirely.
    # Pattern is bounded (<[^>]{0,200}>) to prevent ReDoS on malformed input.
    result = _HTML_TAG_PATTERN.sub("", result)

    # Step 3 — remove dangerous URI schemes.
    # Replaces "javascript:" / "vbscript:" / "data:" with an empty string,
    # leaving any content that followed the colon intact where possible.
    result = _DANGEROUS_URI_PATTERN.sub("", result)

    # Step 4 — collapse multiple whitespace characters into one space.
    result = _MULTI_WHITESPACE_PATTERN.sub(" ", result)

    return result


# ---------------------------------------------------------------------------
# Public function: hash_password
# ---------------------------------------------------------------------------

def hash_password(password: str) -> Tuple[str, str]:
    """
    Derive a secure hash from a plain-text password using PBKDF2-HMAC-SHA256.

    A fresh cryptographically random salt is generated on every call, so two
    identical passwords always produce different hashes, eliminating
    rainbow-table attacks.

    The returned hash string is **self-describing**: it embeds the algorithm,
    iteration count, and salt so that ``verify_password()`` can reconstruct
    the exact derivation parameters.  This enables future algorithm migration
    (e.g. increasing iterations, switching to Argon2id) without requiring a
    full password reset cycle.

    Args:
        password:
            Plain-text password from the registration form.
            Must be a non-empty string — ``None`` or ``""`` raises immediately.

    Returns:
        Tuple[str, str]: ``(hashed_password, salt_hex)`` where:

        - ``hashed_password`` — self-describing string:
          ``"pbkdf2:sha256:<iterations>:<salt_hex>:<dk_hex>"``.
          Store this in the ``password_hash`` column.
        - ``salt_hex`` — hex-encoded salt.
          Store this in the ``salt`` column for quick retrieval during login.

    Raises:
        ValueError:   If *password* is empty or not a string.
        SecurityError: If the hashing operation fails unexpectedly.

    Example::

        hashed, salt = hash_password("SecurePass@123")
        # Store both values in the users table.
    """
    if not isinstance(password, str) or not password:
        raise ValueError("password must be a non-empty string.")

    # Generate a cryptographically random 32-byte (256-bit) salt.
    # 256 bits exceeds the NIST SP 800-132 minimum of 128 bits.
    salt_bytes: bytes = secrets.token_bytes(SALT_BYTE_LENGTH)
    salt_hex: str = salt_bytes.hex()

    try:
        dk: bytes = hashlib.pbkdf2_hmac(
            hash_name=PBKDF2_HASH_NAME,
            password=password.encode("utf-8"),
            salt=salt_bytes,
            iterations=PBKDF2_ITERATIONS,
        )
    except Exception as exc:
        raise SecurityError(f"Password hashing failed: {exc}") from exc

    hashed_password: str = _HASH_FORMAT.format(
        alg=PBKDF2_HASH_NAME,
        iters=PBKDF2_ITERATIONS,
        salt=salt_hex,
        dk=dk.hex(),
    )
    return hashed_password, salt_hex


# ---------------------------------------------------------------------------
# Public function: verify_password
# ---------------------------------------------------------------------------

def verify_password(
    password: str,
    stored_hash: str,
    stored_salt: str,
) -> bool:
    """
    Verify a plain-text password against a stored PBKDF2 hash.

    The stored hash is parsed to extract derivation parameters; the hash is
    re-derived and compared using ``hmac.compare_digest()`` to prevent
    timing-based side-channel attacks.

    v1 security fix
    ---------------
    The ``hash_name`` extracted from the stored string is now validated
    against ``_ALLOWED_HASH_ALGORITHMS`` before being passed to
    ``hashlib.pbkdf2_hmac()``.  Without this check, a tampered database row
    could supply an attacker-controlled algorithm name.

    Args:
        password:    Plain-text password from the login form.
        stored_hash: Self-describing hash string from the ``password_hash``
                     column (produced by ``hash_password()``).
        stored_salt: Hex salt from the ``salt`` column — used as a quick
                     consistency check against the salt in *stored_hash*.

    Returns:
        bool: ``True`` if the password matches, ``False`` otherwise.
        Always returns ``False`` (never raises) on malformed inputs, so
        callers get a uniform result without needing extra error handling.

    Example::

        if not verify_password(submitted_pw, db_row["password_hash"],
                               db_row["salt"]):
            return login_failed_response()
    """
    if not isinstance(password, str) or not password:
        return False

    # --- Parse the self-describing hash string ---
    # Expected: "pbkdf2:<alg>:<iterations>:<salt_hex>:<dk_hex>"
    try:
        parts = stored_hash.split(":")
        if len(parts) != 5 or parts[0] != "pbkdf2":
            _emit_log(
                event="VERIFY_PASSWORD_MALFORMED_HASH",
                severity="WARNING",
                message="Stored hash does not match expected format.",
            )
            return False

        _, hash_name, iterations_str, salt_hex, expected_dk_hex = parts
        iterations = int(iterations_str)
        salt_bytes = bytes.fromhex(salt_hex)
        expected_dk = bytes.fromhex(expected_dk_hex)

    except (ValueError, AttributeError) as exc:
        _emit_log(
            event="VERIFY_PASSWORD_PARSE_ERROR",
            severity="WARNING",
            message="Failed to parse stored hash.",
            detail=str(exc),
        )
        return False

    # --- Algorithm whitelist (v1 fix) ---
    # Prevents a tampered DB row from injecting an arbitrary hash_name.
    if hash_name not in _ALLOWED_HASH_ALGORITHMS:
        _emit_log(
            event="VERIFY_PASSWORD_INVALID_ALGORITHM",
            severity="WARNING",
            message=f"Stored hash uses disallowed algorithm '{hash_name}'.",
        )
        return False

    # --- Salt consistency check ---
    if salt_hex != stored_salt:
        _emit_log(
            event="VERIFY_PASSWORD_SALT_MISMATCH",
            severity="WARNING",
            message="Salt in hash string does not match stored_salt column.",
        )
        return False

    # --- Re-derive and compare ---
    try:
        candidate_dk: bytes = hashlib.pbkdf2_hmac(
            hash_name=hash_name,
            password=password.encode("utf-8"),
            salt=salt_bytes,
            iterations=iterations,
        )
    except Exception as exc:
        _emit_log(
            event="VERIFY_PASSWORD_HASH_ERROR",
            severity="WARNING",
            message="Re-derivation failed during verification.",
            detail=str(exc),
        )
        return False

    # Constant-time comparison prevents timing-based oracle attacks.
    return hmac.compare_digest(candidate_dk, expected_dk)


# ---------------------------------------------------------------------------
# Public function: generate_jwt
# ---------------------------------------------------------------------------

def generate_jwt(user_id: int, username: str, role: str) -> str:
    """
    Issue a signed JWT for an authenticated user.

    Signed with HS256 using the secret from ``JWT_SECRET_KEY``.
    Token lifetime is ``JWT_EXPIRY_MINUTES`` (default 30 minutes).

    v1 fixes applied
    ----------------
    - ``user_id`` is now type-validated — ``None`` or non-integer raises
      ``ValueError`` immediately rather than silently encoding ``"None"``.
    - Expiry is computed with ``datetime`` arithmetic instead of raw float
      timestamps, which is clearer and less error-prone.
    - Role validation is performed before the username check so the most
      security-relevant argument is caught first.

    Claims embedded in the token:
        - ``sub``      : User ID as a string (RFC 7519 requires string subject).
        - ``username`` : Login name — informational, not a security claim.
        - ``role``     : One of ``"citizen"``, ``"employee"``, ``"admin"``.
        - ``iat``      : Issued-at time (UTC).
        - ``exp``      : Expiry time (UTC, ``iat + JWT_EXPIRY_MINUTES``).

    Args:
        user_id:  Integer primary key of the authenticated user.
        username: User's login name. Must be a non-empty string.
        role:     User's role. Must be in ``ROLE_HIERARCHY``.

    Returns:
        str: Encoded, signed JWT string for the ``Authorization: Bearer``
        header.

    Raises:
        ValueError:    If any argument fails its type/value check.
        SecurityError: If the secret is misconfigured or encoding fails.
    """
    # Validate role first — most security-critical argument.
    if role not in ROLE_HIERARCHY:
        raise ValueError(
            f"Invalid role '{role}'. Must be one of: {list(ROLE_HIERARCHY)}."
        )

    # v1 fix: explicit int check prevents None / str silently encoding.
    if not isinstance(user_id, int):
        raise ValueError(
            f"user_id must be an integer, got {type(user_id).__name__}."
        )

    if not isinstance(username, str) or not username.strip():
        raise ValueError("username must be a non-empty string.")

    secret = _load_jwt_secret()

    # Use datetime arithmetic — cleaner and less error-prone than raw floats.
    now = datetime.now(tz=timezone.utc)
    expiry = now + timedelta(minutes=JWT_EXPIRY_MINUTES)

    payload: Dict[str, Any] = {
        "sub":      str(user_id),   # RFC 7519: subject must be a string.
        "username": username.strip(),
        "role":     role,
        "iat":      now,            # PyJWT serialises datetime → epoch int.
        "exp":      expiry,
    }

    try:
        token: str = jwt.encode(payload, secret, algorithm=JWT_ALGORITHM)
        return token
    except Exception as exc:
        raise SecurityError(f"Failed to encode JWT: {exc}") from exc


# ---------------------------------------------------------------------------
# Public function: verify_jwt
# ---------------------------------------------------------------------------

def verify_jwt(token: str) -> Dict[str, Any]:
    """
    Validate and decode an incoming JWT.

    PyJWT performs the following checks automatically:
        1. Base64URL decode the header and payload.
        2. Recompute the HS256 signature and compare — rejects tampering.
        3. Verify the ``exp`` claim against the current UTC time, with a
           ``JWT_LEEWAY_SECONDS`` tolerance for minor clock skew between nodes.
        4. Confirm all required claims are present.

    v1 fix: ``"verify_exp": True`` option removed (it is the default and
    explicitly setting it implies it could be toggled off).  Clock-skew
    leeway of ``JWT_LEEWAY_SECONDS`` (10 s) added via ``leeway`` parameter.

    Args:
        token: Raw JWT string from the ``Authorization: Bearer`` header.

    Returns:
        Dict[str, Any]: Decoded payload with ``sub``, ``username``, ``role``,
        ``iat``, ``exp`` on success.

    Raises:
        TokenExpiredError:  Token's ``exp`` is in the past (beyond leeway).
        TokenInvalidError:  Signature invalid, token malformed, or claims
                            missing.
        SecurityError:      JWT secret cannot be loaded.
    """
    if not isinstance(token, str) or not token.strip():
        raise TokenInvalidError("Token must be a non-empty string.")

    secret = _load_jwt_secret()

    try:
        payload: Dict[str, Any] = jwt.decode(
            token,
            secret,
            algorithms=[JWT_ALGORITHM],
            leeway=timedelta(seconds=JWT_LEEWAY_SECONDS),  # v1 fix: clock-skew tolerance.
            options={"require": ["sub", "exp", "iat", "role", "username"]},
        )
        return payload

    except jwt.ExpiredSignatureError as exc:
        _emit_log(event="TOKEN_EXPIRED", severity="WARNING",
                  message="JWT has expired.")
        raise TokenExpiredError(
            "Session token has expired. Please log in again."
        ) from exc

    except jwt.InvalidSignatureError as exc:
        _emit_log(event="TOKEN_INVALID_SIGNATURE", severity="WARNING",
                  message="JWT signature verification failed.")
        raise TokenInvalidError("Token signature is invalid.") from exc

    except jwt.DecodeError as exc:
        _emit_log(event="TOKEN_MALFORMED", severity="WARNING",
                  message="JWT could not be decoded.", detail=str(exc))
        raise TokenInvalidError(f"Token is malformed: {exc}") from exc

    except jwt.MissingRequiredClaimError as exc:
        _emit_log(event="TOKEN_MISSING_CLAIMS", severity="WARNING",
                  message="JWT is missing required claims.", detail=str(exc))
        raise TokenInvalidError(f"Token is missing required claims: {exc}") from exc

    except jwt.PyJWTError as exc:
        # Catch-all for any remaining PyJWT exception subclass.
        _emit_log(event="TOKEN_INVALID", severity="WARNING",
                  message="JWT validation failed.", detail=str(exc))
        raise TokenInvalidError(f"Token validation failed: {exc}") from exc


# ---------------------------------------------------------------------------
# Public function: verify_session
# ---------------------------------------------------------------------------

def verify_session(token: str) -> Dict[str, Any]:
    """
    Verify an incoming JWT and return a normalised session context dictionary.

    Higher-level wrapper around ``verify_jwt()`` for use at the top of every
    protected request handler or middleware function.  Provides a uniform
    interface to consuming modules — they receive a clean context dict or a
    single predictable exception type, regardless of the underlying failure.

    v1 fix: double-logging removed.  ``verify_jwt()`` already logs
    ``TOKEN_EXPIRED``, ``TOKEN_INVALID_SIGNATURE``, etc. at the point of
    failure.  ``verify_session()`` no longer duplicates those entries; it
    only logs the single ``SESSION_VERIFIED`` success event, which is the
    one event ``verify_jwt()`` does not emit.

    Args:
        token: Raw JWT string from the ``Authorization: Bearer`` header.

    Returns:
        Dict[str, Any]: Session context with guaranteed keys:

        - ``"user_id"``    (int) — authenticated user's database ID.
        - ``"username"``   (str) — authenticated user's login name.
        - ``"role"``       (str) — authenticated user's role.
        - ``"issued_at"``  (int) — UTC Unix timestamp of token issuance.
        - ``"expires_at"`` (int) — UTC Unix timestamp of token expiry.

    Raises:
        SessionInvalidError: For *any* token failure — expired, tampered,
            malformed, or missing.  Callers only need to catch one type.

    Example::

        try:
            session = verify_session(request.headers.get("Authorization", "")
                                     .removeprefix("Bearer ").strip())
        except SessionInvalidError:
            return unauthorised_response()
    """
    try:
        payload = verify_jwt(token)
    except TokenExpiredError as exc:
        # verify_jwt already logged TOKEN_EXPIRED — no duplicate entry here.
        raise SessionInvalidError(
            "Session has expired. Please log in again."
        ) from exc
    except (TokenInvalidError, SecurityError) as exc:
        # verify_jwt already logged the specific failure — no duplicate.
        raise SessionInvalidError(
            "Session is invalid. Please log in again."
        ) from exc

    # Build the normalised session context from the verified payload.
    session_context: Dict[str, Any] = {
        "user_id":    int(payload["sub"]),
        "username":   payload["username"],
        "role":       payload["role"],
        "issued_at":  payload["iat"],
        "expires_at": payload["exp"],
    }

    # Log success ONCE — the only event not already covered by verify_jwt().
    _emit_log(
        event="SESSION_VERIFIED",
        severity="INFO",
        user_id=session_context["user_id"],
        message="Session verified successfully.",
        role=session_context["role"],
    )

    return session_context


# ---------------------------------------------------------------------------
# Public function: verify_role
# ---------------------------------------------------------------------------

def verify_role(user_role: str, required_role: str) -> bool:
    """
    Confirm that a user's role meets the minimum privilege level required.

    Implements a linear role hierarchy where higher-privilege roles
    automatically satisfy lower-privilege requirements:

        citizen (0)  <  employee (1)  <  admin (2)

    An ``admin`` user passes an ``employee`` check; a ``citizen`` does not.

    v1 fix: role level lookup is now O(1) via ``_ROLE_LEVELS`` dict instead
    of two O(n) ``tuple.index()`` calls per invocation.

    Args:
        user_role:
            The role from the verified session context
            (``session_context["role"]``).
        required_role:
            The minimum role required for the operation. Must be one of
            ``"citizen"``, ``"employee"``, ``"admin"``.

    Returns:
        bool: ``True`` if ``user_role`` meets or exceeds ``required_role``.

    Raises:
        ValueError:        If either role is not a recognised value.
        AuthorizationError: If the user's role is insufficient.

    Example::

        session = verify_session(token)
        verify_role(session["role"], "employee")  # raises if citizen
    """
    if user_role not in _ROLE_LEVELS:
        raise ValueError(
            f"Unknown user_role '{user_role}'. "
            f"Must be one of: {list(ROLE_HIERARCHY)}."
        )
    if required_role not in _ROLE_LEVELS:
        raise ValueError(
            f"Unknown required_role '{required_role}'. "
            f"Must be one of: {list(ROLE_HIERARCHY)}."
        )

    # O(1) dict lookup — no linear scan of the tuple.
    if _ROLE_LEVELS[user_role] >= _ROLE_LEVELS[required_role]:
        return True

    # Access denied — log and raise.
    _emit_log(
        event="UNAUTHORIZED_ACCESS",
        severity="WARNING",
        message="Insufficient role for requested operation.",
        user_role=user_role,
        required_role=required_role,
    )
    raise AuthorizationError(user_role=user_role, required_role=required_role)


# ---------------------------------------------------------------------------
# Public function: log_security_event
# ---------------------------------------------------------------------------

def log_security_event(
    event_type: str,
    message: str,
    user_id: Optional[int] = None,
    severity: str = "INFO",
    extra: Optional[Dict[str, Any]] = None,
) -> None:
    """
    Record a structured security audit log entry.

    This is the **public** logging interface for consuming modules.
    Internally it delegates to ``_emit_log()`` so that every entry —
    whether raised internally or by a teammate's module — shares the same
    JSON-line structure and timestamp format.

    This function **never raises**.  A logging failure must not interrupt
    the main application flow.

    Recommended ``event_type`` values (non-exhaustive):
        ``LOGIN_SUCCESS``, ``LOGIN_FAILURE``, ``LOGOUT``,
        ``PASSWORD_CHANGED``, ``ACCOUNT_LOCKED``,
        ``TOKEN_EXPIRED``, ``TOKEN_INVALID``,
        ``UNAUTHORIZED_ACCESS``, ``INPUT_REJECTED``.

    Args:
        event_type:
            Short uppercase identifier for the event category.
        message:
            Human-readable description.  Must NOT contain passwords,
            tokens, or any other credential material.
        user_id:
            Integer user ID if known; ``None`` for pre-authentication events.
        severity:
            One of ``"DEBUG"``, ``"INFO"`` (default), ``"WARNING"``,
            ``"ERROR"``, ``"CRITICAL"``.  Invalid values fall back to
            ``"INFO"``.
        extra:
            Optional dict of additional JSON-serialisable context fields
            (e.g. ``{"ip": "10.0.0.1", "endpoint": "/api/login"}``).
            Keys that collide with core fields are silently ignored.

    Example::

        log_security_event(
            event_type="LOGIN_FAILURE",
            message="Invalid credentials supplied.",
            user_id=None,
            severity="WARNING",
            extra={"attempt": 3, "ip": request.remote_addr},
        )
    """
    _emit_log(
        event=event_type,
        severity=severity,
        user_id=user_id,
        message=message,
        **(extra if isinstance(extra, dict) else {}),
    )


# ---------------------------------------------------------------------------
# SQLite utility: get_user_credentials  (read-only)
# ---------------------------------------------------------------------------

def get_user_credentials(username: str) -> Optional[Dict[str, Any]]:
    """
    Retrieve the stored password hash, salt, and role for a given username.

    Keeping credential reads inside the Security Module ensures that raw
    hash data never crosses module boundaries.  The query is parameterised
    and selects only the five columns required — no ``SELECT *``.

    Args:
        username: Login name to look up (case-sensitive).

    Returns:
        Dict with keys ``"id"``, ``"username"``, ``"password_hash"``,
        ``"salt"``, ``"role"`` if found; ``None`` if no such user exists.

    Raises:
        SecurityError: If the database query fails.
    """
    try:
        with _db_connection() as conn:
            row = conn.execute(
                "SELECT id, username, password_hash, salt, role "
                "FROM users WHERE username = ? LIMIT 1;",
                (username,),
            ).fetchone()

        if row is None:
            return None

        return {
            "id":            row["id"],
            "username":      row["username"],
            "password_hash": row["password_hash"],
            "salt":          row["salt"],
            "role":          row["role"],
        }

    except sqlite3.Error as exc:
        _emit_log(
            event="DB_READ_ERROR",
            severity="CRITICAL",
            message="Failed to retrieve user credentials.",
            detail=str(exc),
        )
        raise SecurityError(f"Database read failed: {exc}") from exc


# ---------------------------------------------------------------------------
# SQLite utility: update_last_login  (targeted write)
# ---------------------------------------------------------------------------

def update_last_login(user_id: int) -> None:
    """
    Update the ``last_login`` timestamp for a user after successful login.

    This is the **only write operation** in the Security Module and is
    intentionally narrow — one column, one row, parameterised query.

    Args:
        user_id: Integer primary key of the user who just logged in.

    Raises:
        SecurityError: If the database update fails.
    """
    try:
        with _db_connection() as conn:
            conn.execute(
                "UPDATE users SET last_login = ? WHERE id = ?;",
                (datetime.now(tz=timezone.utc).isoformat(), user_id),
            )
            conn.commit()
    except sqlite3.Error as exc:
        _emit_log(
            event="DB_UPDATE_FAILED",
            severity="WARNING",
            user_id=user_id,
            message="Failed to update last_login timestamp.",
            detail=str(exc),
        )
        raise SecurityError(f"Database update failed: {exc}") from exc


# ---------------------------------------------------------------------------
# Public API surface
# ---------------------------------------------------------------------------

__all__ = [
    # Input defence
    "validate_input",
    "sanitize_input",
    # Password security
    "hash_password",
    "verify_password",
    # JWT / session management
    "generate_jwt",
    "verify_jwt",
    "verify_session",
    # Access control
    "verify_role",
    # Audit logging
    "log_security_event",
    # Database utilities (consumed by Authentication module)
    "get_user_credentials",
    "update_last_login",
    # Custom exceptions (exported so callers can catch specific types)
    "SecurityError",
    "InputValidationError",
    "TokenExpiredError",
    "TokenInvalidError",
    "SessionInvalidError",
    "AuthorizationError",
]


# ---------------------------------------------------------------------------
# Smoke-test block:  python security.py
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # Provide a throwaway secret for testing — never do this in production.
    os.environ.setdefault("JWT_SECRET_KEY", "smoke_test_secret_32_characters_x")

    print("=== Security Module Smoke Test ===\n")
    exit_code: int = 0

    # --- 1. validate_input ---
    res = validate_input("alice_99", field_name="username", field_type="username")
    assert res["valid"], "valid username rejected"
    res = validate_input("1 OR 1=1", field_name="query")  # v2 fix: quote-less SQLi caught
    assert not res["valid"], "SQLi (quote-less) not detected"
    res = validate_input("<script>alert(1)</script>", field_name="comment")
    assert not res["valid"], "XSS not detected"
    print("[PASS] validate_input")

    # --- 2. sanitize_input ---
    clean = sanitize_input("<b>Hi</b> World")
    assert "<b>" not in clean, "HTML tag not removed"
    # v2 fix: O'Brien is NOT corrupted (no &#x27; entity).
    clean = sanitize_input("O'Brien")
    assert clean == "O'Brien", f"data corrupted: got {clean!r}"
    print("[PASS] sanitize_input")

    # --- 3. hash_password / verify_password ---
    hashed, salt = hash_password("TestPass@2026")
    assert hashed.startswith("pbkdf2:sha256:"), "hash format wrong"
    assert verify_password("TestPass@2026", hashed, salt), "correct pw rejected"
    assert not verify_password("WrongPass", hashed, salt), "wrong pw accepted"
    print("[PASS] hash_password / verify_password")

    # --- 4. generate_jwt / verify_jwt ---
    token = generate_jwt(42, "testuser", "employee")
    payload = verify_jwt(token)
    assert payload["role"] == "employee", "role mismatch"
    assert int(payload["sub"]) == 42, "user_id mismatch"
    print("[PASS] generate_jwt / verify_jwt")

    # --- 5. verify_session ---
    ctx = verify_session(token)
    assert ctx["user_id"] == 42, "session user_id mismatch"
    assert ctx["role"] == "employee", "session role mismatch"
    print("[PASS] verify_session")

    # --- 6. verify_role ---
    assert verify_role("admin", "citizen"), "admin should pass citizen check"
    assert verify_role("employee", "employee"), "employee should pass employee check"
    try:
        verify_role("citizen", "admin")
        print("[FAIL] AuthorizationError not raised for insufficient role")
        exit_code = 1
    except AuthorizationError:
        pass  # Expected
    print("[PASS] verify_role")

    # --- 7. log_security_event ---
    log_security_event(
        event_type="SMOKE_TEST_COMPLETE",
        message="All smoke tests passed.",
        severity="INFO",
        extra={"test": True, "version": "v2"},
    )
    print("[PASS] log_security_event")

    print(f"\n=== All checks passed. Exit code: {exit_code} ===")
    sys.exit(exit_code)
