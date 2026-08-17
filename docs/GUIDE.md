# Implementation Guide — Security & Integration Layer
## Complaint Portal System

**What this file is:** a learning document. It explains what each piece of the
security layer does, why it exists, and how the pieces fit together.

**How to use it:** this is a *starter*. Sections marked `[FILL IN PHASE N]`
get completed by your AI assistant as you finish each phase — the prompts in
`01_PROMPTS.md` instruct it to do exactly that. Everything not marked is
already written for you, and you should read it **before** you start coding.

Copy this file to `docs/GUIDE.md` in your repo at the start of Phase 0.

---

## Table of contents

1. [The big idea](#1-the-big-idea)
2. [Where security lives in MVC](#2-where-security-lives-in-mvc)
3. [The seven-step pipeline](#3-the-seven-step-pipeline)
4. [Module map — what each file does](#4-module-map--what-each-file-does)
5. [Phase 0 — Scaffolding](#phase-0--scaffolding) `[FILL IN]`
6. [Phase 1 — Password hashing](#phase-1--password-hashing) `[FILL IN]`
7. [Phase 2 — JWT tokens](#phase-2--jwt-tokens) `[FILL IN]`
8. [Phase 3 — RBAC](#phase-3--rbac) `[FILL IN]`
9. [Phase 4 — Resource access & IDOR](#phase-4--resource-access--idor) `[FILL IN]`
10. [Phase 5 — Validation & rate limiting](#phase-5--validation--rate-limiting) `[FILL IN]`
11. [Phase 6 — Audit logging & errors](#phase-6--audit-logging--errors) `[FILL IN]`
12. [Phase 7 — The middleware pipeline](#phase-7--the-middleware-pipeline) `[FILL IN]`
13. [Phase 8 — Integration](#phase-8--integration) `[FILL IN]`
14. [How to add a new secured endpoint](#14-how-to-add-a-new-secured-endpoint)
15. [Common mistakes](#15-common-mistakes)

---

## 1. The big idea

Most people building their first web application think of security as a
feature: "we'll add login, and then we'll add permissions." That framing
produces systems where the login works perfectly and the actual data is wide
open, because every developer remembered to check the password and half of
them forgot to check whether the person was allowed to see the specific record
they asked for.

The better framing: **security is a pipeline that every request passes
through before it reaches your business logic.** Not a feature sitting beside
the other features — a layer sitting in front of all of them.

This has a practical consequence for how you build. If security is a feature,
it gets written once per endpoint, inconsistently, by whoever wrote that
endpoint. If security is a pipeline, it gets written *once*, and every
endpoint opts into it with a single line. The second is what you're building.

There's a second idea underneath the first, and it's the one that most often
gets missed in student projects:

> **Authentication is not authorization, and role authorization is not
> resource authorization.**

Three separate questions, three separate checks:

| Question | Name | Example failure if you skip it |
|---|---|---|
| Who are you? | Authentication | Anyone can call the API |
| Is your *role* allowed to do this action? | Role authorization (RBAC) | A citizen can close complaints |
| Are *you* allowed to do it to *this* record? | Resource authorization | A citizen can read anyone's complaint by changing the ID |

The third one is the one that gets skipped, and it's the one that produces
real breaches. It has a name — **IDOR**, Insecure Direct Object Reference —
and Phase 4 is entirely about preventing it.

---

## 2. Where security lives in MVC

Your team is using MVC. The obvious question is: is security a Model, a View,
or a Controller?

None of them. And that's not a gap in MVC — it's a category difference.

- **Models** describe data and its persistence.
- **Views** describe presentation.
- **Controllers** describe what happens when a specific request arrives.

Security is **cross-cutting**: it applies identically to every controller,
which means it can't sensibly live inside any one of them. Code that applies
to everything belongs in a layer of its own.

So your folder structure looks like this:

```
app/
  models/         <- teammates: data + persistence
  views/          <- teammates: serialization / templates
  controllers/    <- teammates: per-endpoint request handling
  security/       <- YOU: the individual checks
  middleware/     <- YOU: the pipeline that runs them in order
  repositories/   <- shared: data access interface
```

`security/` and `middleware/` are **siblings** of `models/` and
`controllers/`, not children. Two different things live in them:

- `security/` holds the *individual capabilities* — hash a password, validate
  a token, check a permission. Each is independently testable and knows
  nothing about HTTP.
- `middleware/` holds the *orchestration* — the thing that calls those
  capabilities in the right order, at the right time, for every request.

The reason to split them: you want to unit-test "does `check_permission` deny
a citizen `UPDATE_STATUS`?" without spinning up a web request, and separately
test "does the pipeline call `check_permission` before it touches the
database?" Two different questions, two different test files.

### Request flow through the layers

```
HTTP request
    |
    v
Router                      (framework)
    |
    v
@secured decorator          <- middleware/pipeline.py  [YOUR CODE]
    |  calls into security/*  for each check
    |  blocks here if any check fails
    v
Controller                  <- controllers/  [TEAMMATE CODE]
    |
    v
Service / Model             <- models/  [TEAMMATE CODE]
    |
    v
Database
```

Notice the controller **never sees an unauthorized request**. That's the
design goal. Your teammates should never need to write an `if user.role ==`
check — if they do, something is wrong with your pipeline and you should fix
the pipeline rather than let them work around it.

---

## 3. The seven-step pipeline

Every protected request runs these, in this order:

| # | Step | Module | Why it's here and not elsewhere |
|---|---|---|---|
| 1 | Token validation | `token_security.py` | Can't check a role you haven't authenticated. Nothing else can run first. |
| 2 | Role check (RBAC) | `rbac.py` | Cheap, in-memory dict lookup. Fail here before doing any I/O. |
| 3 | Resource access | `resource_access.py` | Requires a database read, so it runs *after* the free check. |
| 4 | Rate limiting | `rate_limiter.py` | Before business logic, so an abusive caller can't consume real resources. |
| 5 | Input validation | `input_validation.py` | Reject malformed payloads before they reach any logic that assumes they're well-formed. |
| 6 | Business logic | teammates' controllers | The actual work. Only runs if all of 1–5 passed. |
| 7 | Audit log | `audit_logger.py` | Runs on **both** success and failure. A denied request is exactly the one you want a record of. |

**The ordering is load-bearing.** Two examples of why:

*If you swap 2 and 3:* every request — including ones that were never going
to be allowed at the role level — triggers a database read to fetch the
resource. A citizen hammering `PATCH /complaints/{id}/status` now generates
one DB query per attempt instead of zero. You've turned an authorization bug
into a denial-of-service vector.

*If you move 4 after 6:* the rate limiter still counts the requests, but only
after the business logic already ran them. The limit reports the abuse
accurately and prevents none of it.

**Step 7 is not optional on the failure path.** It's tempting to log only
successes, since those are the "real" events. But the security value of an
audit log is almost entirely in the failures — twelve denied access attempts
on twelve different complaint IDs from one user in thirty seconds is the
signature of someone probing for IDOR, and you'll never see it if you only
log the requests that worked.

---

## 4. Module map — what each file does

Read this table before Phase 1. It's the map of everything you're going to
build, and knowing where you're headed makes each individual phase make more
sense.

### `app/security/`

| File | Responsibility | Depends on |
|---|---|---|
| `security_config.py` | Reads secrets and settings from environment. Single place config enters the app. | nothing |
| `password.py` | Hash and verify passwords; check password strength. | nothing |
| `jwt_tokens.py` | Create citizen and employee tokens. | `security_config` |
| `token_security.py` | Validate, decode, and revoke tokens. Defines `TokenClaims`. | `security_config`, Redis |
| `rbac.py` | Role → permission mapping. Answers "can this *role* do this action?" | nothing |
| `resource_access.py` | Answers "can this *user* do it to *this record*?" IDOR defense. | `token_security`, `repositories` |
| `rate_limiter.py` | Sliding-window request counting. | Redis |
| `input_validation.py` | Pydantic schemas, file validation, filename sanitization. | nothing |
| `audit_logger.py` | Two log streams: business audit, security events. Redaction. | nothing |
| `security_errors.py` | Exception hierarchy + safe error responses. | nothing |

### `app/middleware/`

| File | Responsibility |
|---|---|
| `pipeline.py` | The `@secured` decorator. Orchestrates all of the above in order. |

### `app/repositories/`

| File | Responsibility |
|---|---|
| `base.py` | Abstract `ResourceRepository` interface + `ResourceMeta` dataclass. |
| `in_memory.py` | Fake implementation for tests and for building before models exist. |
| `sql_repository.py` | Real implementation, written in Phase 8 once teammates' models land. |

**Note the dependency column.** Four of these files depend on *nothing* —
`password.py`, `rbac.py`, `input_validation.py`, `security_errors.py`. That's
why you can start today without waiting for anyone. This isn't an accident;
it's the reason the phases are ordered the way they are.

---

## Phase 0 — Scaffolding

`[FILL IN PHASE 0 — your AI will write this section]`

*Should cover: the folder structure created, what each folder is for, who owns
it, why `security/` and `middleware/` are siblings of `models/` rather than
nested inside, and what goes in `.env.example` vs `.env`.*

---

## Phase 1 — Password hashing

`[FILL IN PHASE 1]`

*Should cover: why hash instead of encrypt, what a salt is, why the same
password produces a different hash each time, what argon2id does that SHA-256
doesn't, what a timing attack is, and a function-by-function walkthrough of
`password.py`.*

**Read before this phase:** the reason we never encrypt passwords is that
encryption is *reversible by design*. If your database leaks and passwords
were encrypted, the attacker who also gets the key gets every password in
plaintext. Hashing is one-way: there is no key that reverses it, so the
attacker's only option is to guess. Argon2id then makes each guess
deliberately slow and memory-expensive, so "guess everything" stops being
practical.

---

## Phase 2 — JWT tokens

`[FILL IN PHASE 2]`

*Should cover: the three parts of a JWT, what "stateless" means, why the
payload is readable by anyone, why citizens and employees get different token
shapes, the revocation problem and the Redis denylist, and a line-by-line walk
through `validate_token`.*

**Read before this phase:** a JWT payload is **base64-encoded, not
encrypted**. Anyone holding the token can decode and read every claim in it
without the signing key. The signature proves the claims *haven't been
modified*; it does not hide them. This is the single most misunderstood thing
about JWTs, and it has a direct consequence: never put anything secret in a
token payload. No passwords, no password hashes, no API keys, no personal
data you wouldn't show the user.

**The revocation problem, stated plainly:** a stateless token is valid because
its signature checks out and its expiry hasn't passed. Nothing else is
consulted. So when a user logs out, or an admin disables an account, or a
password is changed after a suspected compromise — the already-issued token
*keeps working* until it expires. The fix is a denylist: a set of revoked
`session_id`s that `validate_token` checks on every call. The entry only needs
to live as long as the token would have, which is why its TTL matches the
token's remaining lifetime rather than being permanent.

---

## Phase 3 — RBAC

`[FILL IN PHASE 3]`

*Should cover: what role-based access control is with a concrete example, why
Enums instead of strings, what fail-closed means, the full role→permission
table, and why this module alone is not sufficient.*

**Read before this phase:** "fail closed" means that when your code doesn't
know the answer, it says no. An unknown role gets no permissions. An
unrecognized permission string is denied. A bug in the lookup denies rather
than allows.

The alternative — fail open — is what you get by accident when you write
something like `if role in DENIED_ROLES: deny`. Now a role you forgot to add
to the list is permitted by default, and adding a new role silently grants it
everything. Always express permissions as an allowlist, never a denylist.

---

## Phase 4 — Resource access & IDOR

`[FILL IN PHASE 4]`

*Should cover: the IDOR walkthrough, why role and resource checks are separate
functions, why "not found" and "not yours" return the same response, what the
repository interface buys you, and the status transition table.*

**Read before this phase — this is the most important concept in your part of
the project.**

Here is the attack, concretely:

1. Citizen A registers a legitimate account and logs in. Everything about
   them is real — real account, real token, real role.
2. They submit a complaint and see it at `GET /api/complaints/101`.
3. They open the browser's network tab, notice the URL, and try
   `GET /api/complaints/102`.
4. If your code only checked "is this a valid token?" and "is this role
   allowed to view complaints?" — both of which are *true* — they now have
   another citizen's complaint.

Nothing was hacked. No password was cracked. The token was genuine and the
role was correct. The application simply never asked the third question: *is
this particular complaint yours?*

This is why `check_permission` and `check_resource_access` are two different
functions in two different files. Collapsing them into one "authorization"
check is how this bug gets written.

**The 404-not-403 rule:** when the answer is "you may not have this," return
the same response as "this does not exist." If you return 403 for complaints
that exist but aren't theirs, and 404 for IDs that don't exist, an attacker
learns which IDs are real by watching which error they get. They can map your
entire complaint database without reading a single record. Same response for
both, always.

---

## Phase 5 — Validation & rate limiting

`[FILL IN PHASE 5]`

*Should cover: validating at the boundary, magic bytes vs extension vs
content-type, path traversal walked through, sliding-window rate limiting,
fail-open vs fail-closed and why login differs, and the rate limit table.*

**Read before this phase:** three pieces of information claim to tell you what
a file is, and you can only trust one of them.

| Source | Who controls it | Trustworthy? |
|---|---|---|
| File extension (`.jpg`) | The client | No — it's just characters in a string |
| `Content-Type` header | The client | No — the client sets it to whatever it wants |
| Magic bytes (first few bytes of content) | The file's actual content | Yes |

A Windows executable renamed to `photo.jpg` and uploaded with
`Content-Type: image/jpeg` passes both of the first two checks and fails the
third, because its first two bytes are `MZ` and not the JPEG signature. Check
the bytes.

**Path traversal**, similarly: a filename is not just a label, it's a
partial path. If a user uploads a file named `../../etc/passwd` and your code
does `open(upload_dir + filename, 'w')`, you have just given them write access
outside your upload directory. `sanitize_filename` strips separators and `..`
sequences for exactly this reason.

---

## Phase 6 — Audit logging & errors

`[FILL IN PHASE 6]`

*Should cover: business audit vs security event logs with example queries,
append-only logs, redaction, why a logging failure must not break a request,
information leakage through errors with a before/after, and correlation IDs.*

**Read before this phase:** the two logs answer different questions and have
different readers.

- **Business audit** answers "what happened to this complaint?" Its reader is
  a department admin resolving a dispute six months later. It records
  successful state changes: who assigned it, who resolved it, when.
- **Security events** answer "is someone attacking us right now?" Its reader
  is you, or a monitoring alert. It records failures: denied access attempts,
  bad tokens, rate limit trips.

Merging them buries the twelve denied attempts inside ten thousand routine
"complaint viewed" entries. Keep them separate.

**On error messages:** compare these two responses to the same failure.

```
Bad:  {"error": "psycopg2.errors.UndefinedColumn: column
       complaints.owner_id does not exist at /app/models/complaint.py:47"}

Good: {"error": "Something went wrong. Please contact support and quote
       reference a3f9c210.", "correlation_id": "a3f9c210"}
```

The first tells an attacker your database engine, your schema, your ORM, your
file layout, and the exact line where something is fragile. The second tells
them nothing — while the full detail sits in your log under that same
correlation ID, findable in one query when the user quotes it to support.

---

## Phase 7 — The middleware pipeline

`[FILL IN PHASE 7]`

*Should cover: what middleware is, where it sits in MVC, all nine steps walked
through in order, what breaks if you reorder, why audit runs on both paths,
and the copy-pasteable example for teammates.*

**Read before this phase:** this is your actual deliverable. Phases 1–6 built
capabilities; this one turns them into a system. The measure of success is
that a teammate can secure a new endpoint by adding one line and cannot
accidentally get it wrong.

---

## Phase 8 — Integration

`[FILL IN PHASE 8]`

*Should cover: the repository swap and what it proves about your interface,
which controllers were changed, any inline checks that were removed and why.*

**Read before this phase:** when you swap `InMemoryResourceRepository` for
`SqlResourceRepository`, **nothing in `app/security/` should need to change,
and no test in `tests/security/` should need editing.** If something does,
your interface leaked implementation details and it's worth understanding
where before you move on. That's the whole payoff of having written against an
abstract interface in Phase 4.

---

## 14. How to add a new secured endpoint

`[EXPAND IN PHASE 8 with the real, working example]`

The intended shape:

```python
@secured(Permission.VIEW_COMPLAINT,
         resource_type="complaint",
         resource_id_arg="complaint_id")
def get_complaint(request, claims, complaint_id):
    # By the time this line runs:
    #   - the token is valid and not revoked
    #   - the role is allowed to view complaints
    #   - THIS user is allowed to view THIS complaint
    #   - the rate limit is not exceeded
    #   - the input is validated
    #   - the audit event will be written when this returns
    return complaint_service.get(complaint_id)
```

Three things a teammate needs to decide, and nothing else:

1. Which `Permission` does this endpoint require?
2. Does it act on a specific resource? If so, `resource_type` and which
   argument holds the ID.
3. Nothing. That's it.

---

## 15. Common mistakes

`[EXPAND IN PHASE 8 as you find real ones in review]`

Things that silently break security in a codebase like this:

- **Calling a service directly from a route, bypassing the decorator.** The
  pipeline only protects what goes through it. A route registered without
  `@secured` is completely open, and nothing will fail or warn you.
- **Adding a `Permission` enum value but forgetting to grant it in the role
  map.** Fails closed, so it's safe — but the feature just doesn't work and
  the cause isn't obvious. The Phase 3 test that asserts every permission is
  granted to at least one role catches this.
- **A controller doing its own `if claims.role == ...` check.** Either the
  pipeline already covers it (duplicate, will drift out of sync) or it doesn't
  (the pipeline has a gap that should be fixed centrally instead).
- **Logging the raw request body.** Registration and login bodies contain
  passwords. This is how secrets end up in log files.
- **Trusting a `user_id` from the request body or query string.** The only
  trustworthy identity is `claims.sub`, which came from a signed token. If a
  handler reads `request.body["user_id"]` and acts on it, a user can act as
  anyone.
- **Catching `SecurityError` inside a controller and continuing.** The
  exception is the denial. Swallowing it turns a blocked request into an
  allowed one.
- **Returning 403 where the guide says 404.** See Phase 4 — it leaks which
  IDs exist.
