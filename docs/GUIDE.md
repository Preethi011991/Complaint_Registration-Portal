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
- Phase 2 — *(to be added)*

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
