# Complaint Portal System

## Folder structure

```
app/
  models/          # Teammates — data models / ORM entities
  views/           # Teammates — response/template rendering
  controllers/     # Teammates — request handlers, route logic
  security/        # Security & integration layer (this owner)
  middleware/      # Security & integration layer (this owner)
  repositories/    # Shared interface layer — data access contracts used
                    # by controllers and security modules alike
tests/
  security/        # Tests for app/security
  middleware/       # Tests for app/middleware
docs/
```

## Ownership

| Folder | Owner |
|---|---|
| `app/models/` | Teammates (data layer) |
| `app/views/` | Teammates (presentation layer) |
| `app/controllers/` | Teammates (request handling layer) |
| `app/security/` | Security owner |
| `app/middleware/` | Security owner |
| `app/repositories/` | Shared — interface contracts consumed by both controllers and security modules |

## `app/security/`

- `password.py` — Argon2 password hashing/verification
- `jwt_tokens.py` — JWT issuance and verification
- `token_security.py` — token revocation/rotation/blacklisting
- `rbac.py` — role-based access control
- `resource_access.py` — resource-level authorization / IDOR protection
- `rate_limiter.py` — Redis-backed request rate limiting
- `input_validation.py` — Pydantic validation/sanitization schemas
- `audit_logger.py` — security event audit logging
- `security_errors.py` — security-layer exception types
- `security_config.py` — environment-driven security configuration

## `app/middleware/`

- `pipeline.py` — wires authentication, RBAC, rate limiting, input
  validation, and audit logging into every request

## Why `security/` and `middleware/` sit alongside `models/`, `views/`, and `controllers/`

They are cross-cutting concerns, not a fourth business-logic layer stacked on
top of MVC. Authentication, authorization, rate limiting, and audit logging
apply identically regardless of which model, view, or controller a request
touches — nesting them inside any one of those folders would tie a
horizontal concern to a vertical layer it doesn't belong to, and no single
MVC layer is the "right" owner:

- Putting security inside `controllers/` conflates request handling with
  request gatekeeping, and tempts every controller to reinvent auth/RBAC
  checks inline instead of going through one shared pipeline.
- Putting it inside `models/` gives data classes responsibility for
  identity, tokens, and access policy — concerns unrelated to what a model
  represents.
- Putting it inside `views/` makes no sense — views render output, they
  don't gate access to it.

Sibling placement also matches the request lifecycle: `middleware/`
intercepts every request *before* it reaches a controller, and `security/`
supplies the primitives that middleware calls (JWT verification, RBAC
checks, rate limits, validation, audit logging). That ordering only makes
sense if security/middleware are peers of MVC, sitting in front of it, not
components inside it.

Finally, this layout matches team ownership: `security/` and `middleware/`
are owned end-to-end by the security/integration engineer, while
`models/`, `views/`, `controllers/` are owned by the rest of the team.
Keeping them as separate top-level packages avoids merge conflicts and makes
ownership boundaries explicit in the file tree itself. `repositories/` is
the one shared interface layer both sides depend on (e.g. resource ownership
lookups needed for IDOR checks), so it's kept separate from both.
