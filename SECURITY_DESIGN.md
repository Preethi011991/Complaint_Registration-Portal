# SECURITY_DESIGN.md
## Complaint Registration Portal — Security Module

---

## 1. Overview

The Security Module is a standalone, reusable Python module responsible for enforcing all security concerns within the Complaint Registration Portal. It acts as a centralized security layer that other modules (Authentication, RBAC, Complaint Management, Task Allocation, and Notification) depend on for cryptographic operations, input safety, token management, access control enforcement, and audit logging.

The module exposes a clean public API so that team members can integrate security controls without needing to understand the underlying cryptographic details.

---

## 2. Objectives

- Protect user credentials through strong, industry-standard password hashing.
- Ensure stateless, tamper-proof session management using JSON Web Tokens (JWT).
- Prevent injection attacks and malformed data from reaching business logic.
- Enforce role-based access at the function level, independent of the RBAC module's database logic.
- Maintain a tamper-evident audit trail of security-relevant events for incident response and compliance.
- Be modular and easy to integrate across all branches of the project without circular dependencies.

---

## 3. Security Algorithms and Justification

| Algorithm / Standard | Purpose | Justification |
|---|---|---|
| **PBKDF2-HMAC-SHA256** | Password hashing | NIST-recommended key derivation function. Applies a configurable iteration count to slow down brute-force and dictionary attacks. Built into Python's `hashlib` — no external dependency required. |
| **Random 16-byte salt** | Password hashing | Ensures two identical passwords produce different hashes, eliminating rainbow table attacks. Generated via `os.urandom()`, which uses the OS cryptographically secure RNG. |
| **HS256 (HMAC-SHA256)** | JWT signing | Symmetric algorithm well-suited for an internal monolith where the same service both issues and verifies tokens. Simple, fast, and widely supported by PyJWT. |
| **JWT (RFC 7519)** | Session tokens | Stateless authentication token. Contains expiry (`exp`), subject (`sub`), and role claims. Avoids server-side session storage, keeping the architecture simple for an MVP. |
| **Input sanitization** | Injection prevention | Strips HTML tags and dangerous characters before data is processed or persisted, mitigating XSS and SQLi risks at the application layer. |

---

## 4. Public Functions

### 4.1 `validate_input(value, field_name, rules)`

Validates that a given input value meets structural and business rules before it enters any business logic.

- Checks for required presence, minimum/maximum length, allowed character sets (e.g., alphanumeric-only for usernames), and format patterns (e.g., email regex).
- Returns a structured result indicating pass/fail and a human-readable reason.
- Used as the first line of defence on any incoming data from request bodies or query parameters.

---

### 4.2 `sanitize_input(value)`

Cleans a string value by removing or escaping characters that could be used in injection or scripting attacks.

- Strips HTML/script tags to prevent stored XSS.
- Removes or escapes SQL meta-characters (`'`, `"`, `;`, `--`) as a secondary defence layer (parameterized queries remain the primary SQLi defence).
- Returns the sanitized string, safe for storage or display.

---

### 4.3 `hash_password(plain_password)`

Derives a secure hash from a plain-text password using PBKDF2-HMAC-SHA256.

- Generates a fresh cryptographically random 16-byte salt on each call.
- Applies a configured number of iterations (minimum 260,000 per current NIST SP 800-132 guidance).
- Returns a single storable string containing the algorithm identifier, iteration count, salt (hex-encoded), and derived key — making the output self-describing for future algorithm migration.

---

### 4.4 `verify_password(plain_password, stored_hash)`

Verifies a plain-text password against a previously stored hash produced by `hash_password()`.

- Parses the stored hash to extract salt, iteration count, and expected digest.
- Re-derives the hash using the same parameters and compares using a constant-time comparison (`hmac.compare_digest`) to prevent timing-based side-channel attacks.
- Returns `True` if the password matches, `False` otherwise.

---

### 4.5 `generate_jwt(user_id, role, expiry_minutes)`

Issues a signed JWT for an authenticated user.

- Encodes the following standard claims: `sub` (user ID), `role`, `iat` (issued-at), `exp` (expiry).
- Signs with HS256 using a secret key loaded from environment configuration, never hardcoded.
- `expiry_minutes` defaults to a short-lived value (e.g., 60 minutes) to limit the blast radius of a stolen token.
- Returns the encoded token string to be handed to the caller (Authentication module).

---

### 4.6 `verify_jwt(token)`

Validates and decodes an incoming JWT.

- Verifies the HS256 signature to confirm the token has not been tampered with.
- Checks the `exp` claim and rejects expired tokens.
- Returns the decoded payload (including `user_id` and `role`) on success, or raises a typed exception on failure (expired, invalid signature, malformed).
- Used by all protected endpoints before any business logic executes.

---

### 4.7 `verify_session(token)`

A higher-level wrapper around `verify_jwt()` intended for use in middleware or request handlers.

- Calls `verify_jwt()` internally.
- Logs a security event on both successful and failed verification attempts.
- Returns a session context object (user ID, role, token issue time) on success.
- Raises a standardized `SessionInvalidError` on any failure, providing a consistent error type for the rest of the application to handle uniformly.

---

### 4.8 `verify_role(session_context, required_role)`

Checks that the authenticated user holds the minimum required role to perform an action.

- Accepts the session context returned by `verify_session()` and a `required_role` string (`citizen`, `employee`, or `admin`).
- Implements a simple role hierarchy: `admin` > `employee` > `citizen`.
- Logs an authorization failure event if access is denied.
- Returns `True` if access is granted, raises `AuthorizationError` otherwise.

---

### 4.9 `log_security_event(event_type, user_id, details, severity)`

Records a structured security audit log entry.

- Captures: timestamp (UTC), event type (e.g., `LOGIN_FAILURE`, `TOKEN_EXPIRED`, `UNAUTHORIZED_ACCESS`, `INPUT_REJECTED`), user ID (if known), severity level (`INFO`, `WARNING`, `CRITICAL`), and a details string.
- Writes to a dedicated security log file (append-only) and optionally to `stderr` for real-time monitoring.
- Log entries are formatted as structured JSON lines for easy parsing by log aggregation tools.
- Does not raise exceptions — logging failures must never disrupt the main application flow.

---

## 5. Overall Security Workflow

The following describes the end-to-end flow for a typical protected request:

```
Incoming HTTP Request
        │
        ▼
┌─────────────────────┐
│  validate_input()   │  ← Reject malformed or oversized data immediately
│  sanitize_input()   │  ← Strip dangerous characters
└────────┬────────────┘
         │
         ▼
┌─────────────────────┐
│  verify_session()   │  ← Extract and validate JWT from Authorization header
│    └─ verify_jwt()  │  ← Check signature and expiry
└────────┬────────────┘
         │
         ▼
┌─────────────────────┐
│  verify_role()      │  ← Confirm user role meets endpoint requirement
└────────┬────────────┘
         │
         ▼
  Business Logic Layer  ← Only reached after all security checks pass
         │
         ▼
┌─────────────────────┐
│ log_security_event()│  ← Audit every significant security decision
└─────────────────────┘
```

**Password operations** (registration/login) follow a separate path:

```
Registration:  plain_password → hash_password() → store hash in DB
Login:         plain_password + stored_hash → verify_password() → generate_jwt() on success
```

---

## 6. Integration Guide

The Security Module is designed to be imported by other modules without modification. The following table shows which functions each module is expected to use.

| Module | Functions Used | Purpose |
|---|---|---|
| **Authentication** | `hash_password()`, `verify_password()`, `generate_jwt()`, `verify_session()`, `log_security_event()` | Register users, verify credentials, issue and validate tokens, log login events |
| **RBAC** | `verify_role()`, `log_security_event()` | Enforce role checks before granting access to role-restricted operations |
| **Complaint Management** | `validate_input()`, `sanitize_input()`, `verify_session()`, `verify_role()` | Validate and sanitize complaint text; ensure only authenticated citizens and employees access relevant endpoints |
| **Task Allocation** | `verify_session()`, `verify_role()`, `log_security_event()` | Ensure only employees/admins can assign or update tasks; log allocation events |
| **Notification** | `verify_session()`, `sanitize_input()`, `log_security_event()` | Confirm the requesting session is valid before sending notifications; sanitize any user-supplied message content |

**Integration steps for any module:**

1. Import the security module: `from security import security_module as sec` (or as per the agreed import path).
2. At the top of each request handler, call `verify_session()` to authenticate and obtain the session context.
3. Call `verify_role()` with the session context and the minimum role required for that endpoint.
4. Pass all user-supplied strings through `validate_input()` and `sanitize_input()` before use.
5. Call `log_security_event()` for any action that should appear in the audit trail.

---

## 7. Security Best Practices Followed

- **No hardcoded secrets.** The JWT secret key and iteration count are read from environment variables or a configuration file excluded from version control.
- **Constant-time comparison.** `hmac.compare_digest()` is used in `verify_password()` to prevent timing attacks.
- **Short-lived tokens.** JWT expiry is kept to 60 minutes by default; refresh token logic is left to the Authentication module.
- **Self-describing password hashes.** The stored hash string includes the algorithm, iteration count, and salt, enabling future algorithm migration without a full password reset.
- **Append-only audit log.** The security log file is opened in append mode and never truncated by the application.
- **Fail-closed design.** All security functions raise exceptions on failure rather than returning `None` or a falsy value, ensuring that a missed check will produce a visible error rather than silent access.
- **Separation of concerns.** The Security Module has no dependency on the database layer, ORM models, or HTTP framework, making it portable and independently testable.
- **Input validation before sanitization.** Validation is applied first to reject structurally invalid input early, reducing the sanitization surface.

---

## 8. Future Improvements

| Improvement | Rationale |
|---|---|
| **Migrate to Argon2id for password hashing** | Argon2id (winner of the Password Hashing Competition) provides stronger resistance to GPU-based attacks. Recommended for post-MVP production. |
| **Asymmetric JWT signing (RS256 / ES256)** | Allows other services to verify tokens without sharing the signing secret, improving security in a microservices architecture. |
| **Refresh token support** | Short-lived access tokens with long-lived refresh tokens improve security without degrading user experience. |
| **Rate limiting integration** | Expose a hook or counter in `log_security_event()` that a rate-limiting middleware can consume to block brute-force login attempts. |
| **Structured log shipping** | Route JSON log lines to a centralized log management system (e.g., ELK stack, AWS CloudWatch) for real-time alerting. |
| **Token revocation list** | Maintain a server-side denylist for invalidated tokens (e.g., after logout or password change) to handle the stateless JWT limitation. |
| **Security unit test suite** | Add `pytest`-based tests for each public function covering both happy-path and adversarial inputs. |

---

*Document version: 1.0 — Prepared for Complaint Registration Portal Security Module (Internship MVP)*
