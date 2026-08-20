# Complaint Portal System — Learning Guide

This document explains, in plain language, what the code in this project
does and why it's built the way it is. It's written for someone learning
the codebase, not someone who already knows it. It grows one phase at a
time — a new section gets added each time a phase of the project is
finished, so it doubles as a running history of how the system came
together.

## Table of contents

- [Phase 0 — Scaffolding](#phase-0--scaffolding)
- [Phase 1 — Password hashing](#phase-1--password-hashing)
- [Phase 2 — JWT tokens](#phase-2--jwt-tokens)
- [Phase 3 — RBAC](#phase-3--rbac)
- Phase 4 — *(to be added)*

## Phase 0 — Scaffolding

Before any real code was written, the project needed a folder structure —
a plan for where every file will live. Setting this up first matters
because it draws the boundaries between different kinds of work, so people
(and future you) know where to look for something, and where to put
something new.

### What is MVC, briefly

The team is using a pattern called **MVC**, short for
**Model–View–Controller**. It splits an application into three kinds of
code:

- **Models** — represent the data. For a complaint portal, a model would
  describe what a "complaint" or a "user" *is*: what fields it has, how
  it's stored.
- **Views** — decide what gets shown to the user. This is the presentation
  layer — the shape of a response, or a rendered page.
- **Controllers** — handle incoming requests and decide what to do with
  them. A controller receives a request like "submit a new complaint,"
  talks to the models, and hands off to a view to produce a response.

MVC is a common pattern because it keeps "what the data is," "how it's
shown," and "what happens when a request comes in" separate, instead of
tangled together in one place.

### The folders, and who owns each one

```
app/
  models/
  views/
  controllers/
  security/
  middleware/
  repositories/
tests/
  security/
  middleware/
docs/
```

**`app/models/`, `app/views/`, `app/controllers/`** — owned by teammates.
This is the standard MVC code described above: the data definitions, the
response rendering, and the request-handling logic for the complaint
portal's actual features (submitting a complaint, viewing its status, and
so on).

**`app/security/`** — owned by the security/integration engineer (that's
the role this guide is written from). This folder holds the building
blocks that keep the system safe:

- `password.py` — turns a plain-text password into a scrambled form (a
  "hash") that's safe to store, and checks a password attempt against it.
  The actual password is never stored anywhere.
- `jwt_tokens.py` — creates and checks **JWTs** (JSON Web Tokens), which
  are the signed, tamper-proof "ID cards" a user's browser holds onto
  after logging in, so they don't have to log in again on every request.
- `token_security.py` — handles what happens to those tokens over time:
  cancelling ("revoking") a token early, e.g. on logout, and rotating them
  out for new ones.
- `rbac.py` — short for **Role-Based Access Control**. This decides what a
  user is *allowed to do* based on their role (e.g. "citizen" vs "portal
  admin"). An admin might be allowed to close any complaint; a citizen
  might only be allowed to view their own.
- `resource_access.py` — protects against **IDOR** (Insecure Direct Object
  Reference), a specific bug pattern where a user can access someone
  else's data just by guessing or changing an ID in a request (for
  example, changing `/complaints/104` to `/complaints/105` and seeing a
  stranger's complaint). This module checks not just "is this user allowed
  to view complaints" but "does this user own *this specific* complaint."
- `rate_limiter.py` — limits how many requests a user or IP address can
  make in a given time window, to prevent abuse like someone hammering the
  login form to guess passwords.
- `input_validation.py` — checks that data coming into the system (a
  complaint's text, a user's email, etc.) is well-formed and safe before
  it's used anywhere else, catching bad or malicious input early.
- `audit_logger.py` — keeps a record of security-relevant events (logins,
  failed access attempts, admin actions) so there's a trail to look back
  on if something goes wrong.
- `security_errors.py` — defines the specific error types this layer can
  raise (e.g. "token expired," "not authorized"), so the rest of the
  system can handle them consistently.
- `security_config.py` — reads security-related settings (like the JWT
  signing key or token expiry time) from environment variables, so secrets
  never get hard-coded into the source code.

**`app/middleware/`** — also owned by the security/integration engineer.
A **middleware** is code that runs automatically on *every* request,
before it reaches a controller — think of it as a checkpoint every request
has to pass through. `pipeline.py` is where the individual security
pieces above (authentication, RBAC, rate limiting, input validation, audit
logging) get chained together into that checkpoint.

**`app/repositories/`** — a shared layer both sides depend on. A
repository is a go-between for data access: instead of controllers and
security code each writing their own database queries, they call a
repository, which handles the actual lookup. This matters for security
specifically because checks like "does this user own this complaint"
(IDOR protection) need to look up who owns a resource — that lookup goes
through a repository so it's defined in one place instead of duplicated.

**`tests/security/`, `tests/middleware/`** — automated tests for the
security and middleware code, mirroring the structure of `app/`.

**`docs/`** — project documentation, including this guide.

### Why `security/` and `middleware/` are *siblings* of `models/`, `views/`, `controllers/` — not nested inside them

It would be possible to put, say, authentication code inside
`controllers/`, since controllers are what check whether a request is
allowed. But that would be the wrong home for it, for a few reasons:

1. **Security applies everywhere, not to one layer.** Authentication,
   RBAC, rate limiting, and audit logging don't care whether a request is
   about a model, a view, or a controller — they apply the same way to
   *every* request, regardless of what it touches. A concern that cuts
   across all three MVC layers like this is usually called a
   **cross-cutting concern**. Nesting it inside any one layer would
   misrepresent what it actually does.

2. **No single MVC layer is the right owner.**
   - Inside `controllers/`, it would blur "handling a request" with
     "deciding if this request is even allowed to happen," and would tempt
     every controller to write its own ad hoc security checks instead of
     relying on one shared, consistent system.
   - Inside `models/`, data classes would end up responsible for things
     like tokens and access policy, which have nothing to do with what
     the data itself represents.
   - Inside `views/` it wouldn't make sense at all — views are about
     rendering output, not deciding who's allowed to see it.

3. **The request lifecycle matches this layout.** `middleware/` runs
   *before* a request ever reaches a controller, and it calls into
   `security/` to do its checks. That ordering only makes sense if
   `security/` and `middleware/` sit in front of the MVC layers, not
   inside one of them.

4. **It matches who owns what.** `security/` and `middleware/` are owned
   end-to-end by one person; `models/`, `views/`, `controllers/` are owned
   by the rest of the team. Keeping them as separate top-level folders
   makes that division obvious just from looking at the file tree, and
   avoids everyone's changes colliding in the same files.

`repositories/` sits apart from both for a related reason: it's not owned
by one side or the other — it's the shared contract both sides call into
for data access, including the ownership lookups the security layer needs
for IDOR checks.

## Phase 1 — Password hashing

This phase built `app/security/password.py`, the code responsible for
turning a user's password into something safe to store, and safely
checking a login attempt against it.

### Why we hash passwords instead of encrypting or storing them

There are three ways you could handle a password: store it as-is
("plaintext"), **encrypt** it, or **hash** it. Only one of these is safe.

Storing a password as plaintext means that anyone who gets access to the
database — an attacker, a careless employee, a backup left somewhere
unprotected — can read every user's actual password immediately. That's
obviously bad, and also means the portal itself now knows every user's
password, which it should never need to.

Encryption might sound safer, but encryption is designed to be
*reversible*: whoever holds the encryption key can turn the encrypted
password back into the original plaintext. If an attacker steals the
database **and** the key (which often live near each other), they get
every plaintext password back. Encryption is the right tool when you need
to recover the original value later — but a login system never needs to
recover the original password, it only needs to check "does this attempt
match what the user set." That's a different problem, with a different
tool.

**Hashing** solves that problem correctly. A hash function takes an input
(the password) and produces a fixed-size, scrambled output (the hash) —
and it's a *one-way* transformation: there's no key or process that turns
the hash back into the original password. To check a login attempt, the
system hashes the attempt the same way and compares the two hashes,
without ever needing to know the original password again. If the database
is stolen, the attacker only gets hashes, not passwords.

### What a salt is, and why `hash_password` gives a different output every time

If two users pick the same password, a plain hash function would produce
the *same* hash for both of them. That's a problem: an attacker who
precomputes the hashes of millions of common passwords (a "rainbow table")
could instantly spot which stored hashes match, for every user at once.

A **salt** fixes this. It's a random value generated fresh for every
password, mixed in before hashing, so the same password produces a
different hash every time. `hash_password` in `password.py` doesn't
generate or store a salt separately — Argon2id does this automatically:
every call to `_hasher.hash(...)` generates its own random salt and
embeds it directly inside the returned hash string, alongside the
algorithm settings that were used. That's why `test_password.py` can
assert that hashing the same password twice gives two different results,
and it's also why `verify_password` doesn't need a salt passed in
separately — it's already inside `password_hash`.

### What Argon2id is, and why it's preferred over bcrypt/SHA-256 here

Not all hash functions are good for passwords. Something like SHA-256 is
built to be *fast*, because it's normally used for things like checksums,
where speed is a feature. For passwords, speed is a liability: an attacker
who steals a database of SHA-256 hashes can try billions of password
guesses per second on ordinary graphics hardware, so weak or common
passwords fall almost instantly.

**Argon2id** is a *memory-hard* algorithm, purpose-built for password
hashing. It deliberately requires a meaningful amount of memory and CPU
time to compute a single hash. A real login only ever needs to do this
once per attempt, so the cost is invisible to users — but an attacker
trying millions of guesses pays that same cost millions of times over,
which makes large-scale cracking impractical. This project uses the
"id" variant specifically because it combines resistance to GPU-based
cracking attacks with resistance to certain side-channel attacks, which is
why it's the current recommended choice (over plain Argon2i, Argon2d, and
also over the older `bcrypt`, which doesn't scale its memory cost the same
way and is showing its age against modern cracking hardware).

### What a timing attack is, and how `verify_password` avoids one

A **timing attack** is a way of extracting secret information not from
*what* a program returns, but from *how long* it takes to return it.

Imagine comparing two strings character by character, left to right, and
stopping as soon as you hit a mismatch. A guess that happens to share more
correct leading characters with the real value will take very slightly
longer to reject, because the comparison gets further before it fails.
That difference is a matter of nanoseconds, but if an attacker can send
the same request repeatedly and measure response times carefully, they
can use those tiny differences to reconstruct a secret one character at a
time — without ever seeing it directly.

`verify_password` avoids this by never comparing strings itself. It hands
the comparison off entirely to `_hasher.verify(...)`, argon2-cffi's own
verification method, which is written to take a consistent amount of time
regardless of where — or whether — a mismatch occurs. This matters most at
a login endpoint, since that's the one place in the system where an
attacker can realistically make repeated, timed attempts.

### Why `validate_password_strength` returns a list of reasons instead of a bool

A function that just returns `True` or `False` can only tell the caller
*whether* a password is acceptable, not *why* it isn't. If a password
fails for two reasons at once — say, it's too short **and** has no digit
— a plain boolean forces the UI to either guess, or make the user
resubmit repeatedly, discovering one problem at a time.

`validate_password_strength` instead returns a tuple: an overall
`True`/`False`, and a list of every rule that failed. That way, the
calling code (eventually a controller or a view) can show the user a
complete list of what needs to change, all at once, on the very first
attempt.

### Walking through the code

The file opens with a module-level comment stating a hard rule for
everything below it:

```python
"""Password hashing and verification (Argon2id).

No function in this file may log, print, or otherwise emit a plaintext
password, in any form (including exceptions or debug output).
"""
```

This exists because it's easy to accidentally leak a password through a
debug `print`, a log line, or an exception message that includes function
arguments. Stating the rule up front, in one place, means every future
change to this file gets checked against it.

```python
_hasher = PasswordHasher()
```

This creates one shared `PasswordHasher` instance (from argon2-cffi) for
the whole module, configured with Argon2's default, currently-recommended
memory/time-cost settings. Both `hash_password` and `verify_password` use
this same instance.

```python
def hash_password(plain_password: str) -> str:
    ...
    return _hasher.hash(plain_password)
```

`hash_password` is a thin wrapper: it hands the plaintext password to
argon2-cffi and returns the resulting hash string. As covered above, that
one call is doing a lot of work — it generates a random salt, applies the
Argon2id algorithm with its memory/time cost, and packs the salt,
parameters, and resulting hash into a single string that's safe to store
in the database.

```python
def verify_password(plain_password: str, password_hash: str) -> bool:
    ...
    try:
        return _hasher.verify(password_hash, plain_password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False
```

`verify_password` re-derives the hash of `plain_password` using the same
salt and parameters stored inside `password_hash`, and compares the two —
using argon2-cffi's constant-time `verify`, not `==`. The `try`/`except`
is what makes this function safe to call on any input: `VerifyMismatchError`
means the password was simply wrong, but `VerificationError` and
`InvalidHashError` cover cases where `password_hash` itself is broken —
truncated, corrupted, or not a real Argon2 hash at all. Without catching
those, a single bad row in the database could throw an unhandled
exception and crash the login endpoint for that user. Catching them and
returning `False` instead means "this login attempt is rejected," which
is the correct, safe outcome either way.

```python
def validate_password_strength(password: str) -> tuple[bool, list[str]]:
    failure_reasons: list[str] = []

    if len(password) < _MIN_LENGTH:
        failure_reasons.append(f"Password must be at least {_MIN_LENGTH} characters long.")

    if not any(char.isalpha() for char in password):
        failure_reasons.append("Password must contain at least one letter.")

    if not any(char.isdigit() for char in password):
        failure_reasons.append("Password must contain at least one digit.")

    return (len(failure_reasons) == 0, failure_reasons)
```

This function checks all three rules independently — length, "has a
letter," "has a digit" — instead of stopping at the first failure. Each
`if` appends its own message to `failure_reasons` only if that specific
rule fails, so a password that's both too short and missing a digit
collects both messages. The final line derives `is_valid` from whether
*any* reasons were collected, rather than tracking it separately, so the
boolean and the list can never disagree with each other.

## Phase 2 — JWT tokens

This phase built `app/security/jwt_tokens.py` (issuing tokens) and
`app/security/token_security.py` (validating them, and revoking them
early). Together they answer two questions every request needs answered:
"who is making this request" and "is that still true right now."

### What a JWT is, and what "stateless" means here

A **JWT** (JSON Web Token) is a compact, signed string a server hands to a
user after they log in, and which the user's browser then sends back on
every later request, in place of logging in again each time. It's made of
three parts, separated by dots, each written in a URL-safe encoding called
base64url:

```
eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1MSIsInJvbGUiOiJDSVRJWkVOIn0.YKUF0SNhJoJEYesf...
└────── header ──────┘└──────────── payload ────────────┘└──── signature ────┘
```

- **Header** — small metadata about the token, mainly which signing
  algorithm was used (here, `HS256`).
- **Payload** — the actual claims: who this token is for, their role,
  when it was issued, when it expires. This is the part `jwt_tokens.py`
  builds and `token_security.py` reads.
- **Signature** — a cryptographic stamp computed from the header, the
  payload, and the server's secret key (`jwt_secret`, from
  `security_config.py`). Only someone holding that secret can produce a
  signature that matches — which is what makes the token trustworthy.

"**Stateless**" means the server doesn't need to keep a database record of
every logged-in session to know a token is legitimate. It can check the
signature using only the secret it already has, entirely offline, with no
lookup required. That's efficient — but as the revocation section below
explains, it's also exactly what makes "logging someone out early"
harder than it sounds.

### Why the payload is readable by anyone, and what that means for what goes in it

Base64url is not encryption — it's just a way of representing bytes using
letters, digits, and a couple of symbols, so they're safe to put in a
URL. Anyone can reverse it instantly, with no key and no secret required
(try pasting any JWT into a site like jwt.io — the payload shows up in
plain text immediately). The signature proves the payload *hasn't been
tampered with*; it does nothing to hide what's inside it.

That means anything placed in the payload should be treated as public to
whoever holds the token — which includes the user's own browser, any
proxy or CDN the request passes through, and browser extensions or
malware that might read local storage. This is why `jwt_tokens.py` opens
with a rule, in its module docstring, that a token payload must never
contain a password, a password hash, or an email address. A leaked
password hash could be brute-forced offline; a leaked email is personal
data the token has no reason to expose. The claims actually used —
`sub` (user id), `role`, `session_id`, timestamps, and `department_id` for
employees — are all things the token is *supposed* to reveal to its own
holder, so there's nothing unsafe about them being readable.

### Why citizens and employees get different token shapes

A citizen using the portal and an employee working it are answering a
different question: "who is this person" versus "who is this person, and
what can they do, and where do they work." An employee's permissions
depend on their `role` (e.g. "AGENT" vs "ADMIN") and their
`department_id` (an agent in the billing department shouldn't
automatically see complaints routed to the technical department) —
neither of which a citizen token needs, since citizens aren't assigned
roles or departments.

Rather than force one bloated shape onto both (citizen tokens carrying a
meaningless `department_id: null`, or worse, guessing wrong department
defaults), `generate_citizen_token` and `generate_employee_token` each
produce exactly the claims their use case needs. `initialize_jwt_token`
exists as a single entry point that dispatches to the right one based on
`role`, so callers that don't already know which shape they need can
just ask for a token by role.

### The revocation problem

Here's the tension: a JWT's whole design is to let the server verify it
*without* checking a database — that's what "stateless" bought us. But
that means once a token is issued, it stays valid until its `exp`
timestamp arrives, no matter what happens in between. If a user logs out,
or an admin needs to force-end a compromised session *right now*, there's
no way to edit an already-issued, already-signed token to say "never
mind." The token itself has no memory of anything that happens after it
was created.

So cancelling a token early can't be done by changing the token — it has
to be done by giving the server a separate place to remember "this
session should stop being trusted," and checking that memory every time a
token comes in. That's a **side channel**: a piece of state that sits
next to the stateless token, specifically to reintroduce the one
capability a purely stateless design gave up.

`token_security.py` implements this as a **denylist** (a list of things
explicitly rejected, as opposed to an "allowlist" of things explicitly
permitted) stored in Redis:

- `revoke_token(session_id, user_id)` writes the session id into Redis
  with a time-to-live (TTL) equal to how long a token for that session
  could still be valid.
- `is_token_revoked(session_id)` checks whether that session id is
  currently present.
- `validate_token` calls `is_token_revoked` on every check, so a revoked
  session is rejected on its very next use, even though the token itself
  is technically still "valid" by its signature and expiry alone.

The TTL matters: once a token would have expired naturally anyway, its
revocation entry is pointless dead weight, since the expiry check would
already reject it. Matching the TTL to the token's remaining lifetime
means Redis only ever holds entries for sessions that are revoked *and*
could otherwise still pass validation — keeping the denylist small and
self-cleaning, instead of growing forever.

Redis is used here (rather than, say, a regular SQL table) because it's
built for exactly this kind of fast, short-lived, expiring key lookup, and
because the code checks it on *every single request* — it needs to be
fast. `token_security.py` doesn't hard-wire itself to Redis, though: it
defines a small `RevocationStore` interface with two methods
(`set_with_ttl`, `exists`), and `RedisRevocationStore` is just one
implementation of it. `InMemoryRevocationStore` is a second
implementation used by the test suite, so tests never need a real Redis
server running to check revocation logic.

### Why four exception types instead of returning False

A function like `validate_token` could just return `True`/`False` for
"is this token good." But a boolean throws away *why* it failed — and
that "why" often needs to drive genuinely different behavior, not just a
generic "access denied" message:

- An **expired** token usually just means the user's session timed out —
  the normal, expected response is to silently use a refresh token, or
  redirect to login without alarm.
- An **invalid** token (bad signature, tampered payload, garbage input) is
  a sign of something actively wrong — a forged or corrupted token — and
  might be worth logging as a security event.
- A **revoked** token means someone (the user, or an admin) deliberately
  ended this session — the user should be sent to login, not silently
  refreshed, since a refresh would defeat the whole point of revoking it.
- A **wrong token type** (e.g. a citizen token used where an employee
  token was expected) is a sign the caller is hitting the wrong endpoint
  entirely, which is a different bug class from "this token is broken."

Collapsing all four into one `False` would force every caller to
re-derive which of these happened by some other means, or to treat them
identically when they shouldn't be. Four distinct exception types, all
sharing one `SecurityError` base (in `security_errors.py`), let callers
catch broadly (`except SecurityError`) when they don't care which one
happened, or narrowly (`except RevokedTokenError`) when the distinction
matters — without ever guessing.

### Walking through `validate_token`

```python
def validate_token(token: str, expected_user_type: str | None = None) -> TokenClaims:
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
```

The very first thing this does is ask PyJWT to decode the token *and*
verify its signature against `config.jwt_secret`, in one call. This has
to be the first check, because every later check trusts the payload's
contents — if the signature weren't verified first, an attacker could
hand in a token with a forged payload (say, `role: "ADMIN"`) and every
check after this point would happily believe it. `algorithms=[...]` is
also a deliberate safety measure: without pinning the expected algorithm,
a malicious token could claim to use a different, weaker algorithm and
trick a careless implementation into accepting it. The `require` option
makes sure the claims this code depends on later are actually present,
rather than failing with a confusing `KeyError` further down.

PyJWT itself checks expiry as part of `decode()`, which is why
`jwt.ExpiredSignatureError` is caught separately from the general
`jwt.InvalidTokenError` — this is what turns PyJWT's own errors into this
project's `ExpiredTokenError` and `InvalidTokenError`.

```python
    session_id = payload["session_id"]
    if is_token_revoked(session_id):
        raise RevokedTokenError(f"Session {session_id!r} has been revoked.")
```

Only after the token is confirmed genuine and unexpired does it check the
Redis denylist. This has to come *after* signature verification — checking
revocation on a forged token would be pointless, since a forged token was
never a real session to begin with. It comes *before* the role check
below because a revoked session should always be rejected as "revoked,"
regardless of what role was expected — that's a more useful, more
specific answer than a generic mismatch.

```python
    role = payload["role"]
    if expected_user_type is not None and role != expected_user_type:
        raise WrongTokenTypeError(
            f"Expected token role {expected_user_type!r}, got {role!r}."
        )

    return _claims_from_payload(payload)
```

The role check runs last, once the token is already known to be
genuine, current, and not revoked. Only at that point does it make sense
to ask "but is this the *right kind* of token for this endpoint" — there
would be no point checking that on a token that's forged or already
expired anyway.

The ordering as a whole — signature, then expiry, then revocation, then
role — moves from "is this token real at all" to "is it still valid
right now" to "is it the right kind for this request," so each check
only ever runs once every check before it has already passed. That's
also why the caller always gets the *most specific* applicable error: a
revoked, wrong-type token still reports as revoked, because that's true
regardless of role, and a forged token never reaches the role check at
all.

## Phase 3 — RBAC

This phase built `app/security/rbac.py`, which decides what a user is
*allowed to do* based on their role. Phase 2 answered "who is making this
request" (via a validated token); this phase answers "is that person
allowed to do the thing they're trying to do."

### What role-based access control is, with an example from this system

**Role-based access control (RBAC)** is a way of managing permissions by
grouping users into **roles**, and granting **permissions** to the role
rather than to each individual user one at a time. Instead of an admin
having to decide, person by person, "can Alice resolve complaints? Can
Bob?", the system defines a role like `DEPARTMENT_OFFICER` once, decides
what that role can do, and then every user assigned that role
automatically gets those abilities.

Concretely, in this portal: a citizen who logs in gets the `CITIZEN`
role, which lets them create a complaint (`CREATE_COMPLAINT`) and check on
it later (`VIEW_COMPLAINT`) — but a citizen can never mark a complaint
resolved, because `RESOLVE_COMPLAINT` is only granted to
`DEPARTMENT_OFFICER`, `DEPARTMENT_ADMIN`, and `SYSTEM_ADMIN`. If someone
tried calling `check_permission(Role.CITIZEN, Permission.RESOLVE_COMPLAINT)`
anywhere in the app, it returns `False` — no matter which citizen, and no
matter which complaint. That's the essence of RBAC: the answer depends
only on the *role*, not on anything specific to the person or the
complaint.

### The full role → permission table

| Permission | CITIZEN | DEPARTMENT_OFFICER | DEPARTMENT_ADMIN | SYSTEM_ADMIN |
|---|---|---|---|---|
| CREATE_COMPLAINT | ✅ | | | ✅ |
| VIEW_COMPLAINT | ✅ | ✅ | ✅ | ✅ |
| UPDATE_STATUS | | ✅ | ✅ | ✅ |
| ASSIGN_COMPLAINT | | | ✅ | ✅ |
| RESOLVE_COMPLAINT | | ✅ | ✅ | ✅ |
| SUBMIT_FEEDBACK | ✅ | | | ✅ |
| UPLOAD_ATTACHMENT | ✅ | ✅ | ✅ | ✅ |
| VIEW_AUDIT_LOGS | | | ✅ | ✅ |
| MANAGE_USERS | | | | ✅ |

This table is a direct reflection of the `_ROLE_PERMISSIONS` dict in
`rbac.py` — if the two ever disagree, the code is the source of truth and
this table needs updating.

### Why Enums instead of strings

`Role` and `Permission` are both defined as Python `Enum` classes (backed
by `str`, so they still print and serialize as familiar strings like
`"CITIZEN"`), rather than just passing raw strings like `"citizen"`
around the codebase.

The reason is what happens when someone gets a name slightly wrong. If
permissions were bare strings, a typo like `"RESOLV_COMPLAINT"` (missing
an E) wouldn't fail anywhere — the check `permission in role_permissions`
would just quietly evaluate to `False` forever, because the misspelled
string will never appear in the mapping. That's a *silent permission
bug*: something that looks like "access correctly denied" in every test
and every log, when it's actually "this permission can never be granted
to anyone, because of a typo, and nobody will notice."

With `Enum`, that typo can't be written at all — `Permission.RESOLV_COMPLAINT`
doesn't exist, so referencing it raises an `AttributeError` immediately,
at the moment the code runs (and for most editors/type-checkers, before
it even runs). A crash at import time, pointing at the exact line with
the typo, is far easier to catch and fix than a silent, permanent access
bug discovered months later when someone asks "why can no one ever
resolve a complaint?"

### What "fail closed" means, and why this module defaults to deny

**Fail closed** means that when a check can't be resolved cleanly — an
unrecognized input, a missing configuration, an unexpected error — the
system defaults to *denying* access rather than allowing it. The
opposite, **fail open**, defaults to *allowing* access when something
goes wrong, so that the failure doesn't block anyone.

Fail open is sometimes the right choice for a non-security feature —
if a recommendation engine crashes, "just show nothing" is a fine
default. It's the wrong choice for anything that gates access, because it
means a bug can silently turn a permission check into an open door.

`rbac.py` fails closed in two places. First, `check_permission` only
returns `True` if the permission is *explicitly* present in that role's
granted set — there is no fallback branch anywhere that defaults to
allow. Second, and more importantly, looking up an **unrecognized role**
raises `UnknownRoleError` rather than quietly returning an empty
permission set. An empty set might sound just as safe (it also denies
everything) — but a silent empty set is indistinguishable from a role
that's correctly configured with zero permissions, so a misconfigured or
mistyped role would look identical to "working as intended" in every log
and every test. Raising loudly instead forces the mistake to surface
immediately, as a crash pointing at the actual bug, rather than as a
permission bug in production nobody notices until someone reports being
wrongly blocked (or worse, wrongly let in, if the bug is elsewhere and
"empty means deny" turns out not to hold everywhere it's assumed).

### Why this module alone is not enough

RBAC as built here answers one question: "can a user with this **role**
perform this **kind** of action, in general." It deliberately does not
know anything about *which* complaint is being acted on, or who filed it.

That's a real gap. Consider: `check_permission(Role.CITIZEN,
Permission.VIEW_COMPLAINT)` returns `True` — citizens are allowed to view
complaints. But that's not the same question as "can *this* citizen view
*this specific* complaint." If the system only ever asked the first
question, any logged-in citizen could view *any* complaint in the portal
just by changing an ID in the URL — a real, common vulnerability called
**IDOR** (Insecure Direct Object Reference), where "am I allowed to do
this kind of thing" gets mistaken for "am I allowed to do this to this
specific object."

`rbac.py`'s own comment above the permission mapping states this
explicitly: it's a role-level check only, and a permission granted here
is *necessary but not sufficient* — it's the first gate, not the only
one. The second question — ownership and department-scoped access, i.e.
"does this complaint belong to this citizen," "is this officer allowed to
touch complaints outside their own department" — is handled by
`resource_access.py`, which is what Phase 4 builds.
