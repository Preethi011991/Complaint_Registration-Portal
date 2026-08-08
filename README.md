# Complaint Registration Portal

A Flask-based complaint registration and classification system with role-based access control (RBAC). Citizens register and raise complaints, a keyword-based classifier automatically categorizes them (Electricity / Water / Social), and the system auto-assigns each complaint to the least-busy Staff Officer. System Admins manage users, complaints, feedback, and can generate audit reports.

> **Note:** This project is the foundation for implementing a **security system** covering the complaint **classification** pipeline and the **RBAC** layer, plus **push notifications**. The complete function reference below is provided so every function can be secured/hardened, and the dedicated sections at the end state exactly **where** notifications and security checks must be implemented.

---

## Table of Contents

- [Roles (RBAC)](#roles-rbac)
- [Tech Stack](#tech-stack)
- [Installation](#installation)
- [Email Configuration](#email-configuration)
- [Database Models](#database-models)
- [Function Reference](#function-reference)
  - [Auth Decorators](#auth-decorators)
  - [Helper Functions](#helper-functions)
  - [Classification & Assignment Functions](#classification--assignment-functions)
  - [Route / View Functions](#route--view-functions)
- [Route Map](#route-map)
- [Project Structure](#project-structure)
- [Utility Scripts](#utility-scripts)
- [Push Notifications - Where to Add Them](#push-notifications---where-to-add-them)
- [Security System - Where to Implement It](#security-system---where-to-implement-it)

---

## Roles (RBAC)

The system has three roles, seeded on first run. Each user gets a unique **identity number** with a role prefix.

| Role            | Identity Prefix | Access |
|-----------------|-----------------|--------|
| Citizen         | `CIT`           | Raise complaints, view own complaints, track status, give feedback |
| Staff Officer   | `STF`           | View assigned complaints, mark tasks completed, view profile |
| System Admin    | `ADM`           | Dashboard with stats, manage users/complaints/feedback, audit reports, edit own profile |

Identity numbers are generated as `PREFIX` + zero-padded sequence, e.g. `CIT000001`, `STF000003`, `ADM000001`.

---

## Tech Stack

- **Backend:** Python 3 + Flask
- **ORM / Database:** SQLAlchemy 2.x + SQLite (`db.sqlite3`)
- **Authentication:** Werkzeug password hashing (`generate_password_hash` / `check_password_hash`)
- **Email:** Flask-Mail (SMTP / Gmail)
- **Templating:** Jinja2 (`templates/`)
- **Frontend:** HTML + CSS (`static/`)

---

## Installation

```bash
# 1. Clone / enter the project directory
cd classification

# 2. (Recommended) Create and activate a virtual environment
python -m venv venv
venv\Scripts\activate        # Windows
source venv/bin/activate    # Linux / macOS

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run the application
python main.py
```

The app starts in debug mode at `http://127.0.0.1:5000`.

---

## Email Configuration

The app sends the generated identity number to the user's email on successful signup, using Gmail's SMTP server. Credentials are currently hard-coded in `main.py`:

```python
app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USERNAME"] = "shamikshab20228042@gmail.com"
app.config["MAIL_PASSWORD"] = "..."       # Gmail App Password
```

> **Security note:** Move credentials to environment variables or a `.env` file (loaded via `python-dotenv`) before deployment.

---

## Database Models

All models are declared in `main.py` with SQLAlchemy's declarative base. Tables are auto-created on startup (`Base.metadata.create_all(engine)`).

| Model                    | Table                    | Purpose |
|--------------------------|--------------------------|---------|
| `Role`                   | `roles`                  | Role names: Citizen, Staff Officer, System Admin |
| `User`                   | `users`                  | Account with identity number, name, email, hashed password, role |
| `Complaint`              | `complaints`             | Complaint title, description, location, status, citizen reference |
| `ComplaintClassification`| `complaint_classification` | Auto-computed category, priority, confidence per complaint |
| `ComplaintAssignment`    | `complaint_assignment`   | Links a complaint to the assigned Staff Officer |
| `Feedback`               | `feedback`               | Citizen rating and comments for a complaint |

Relationship summary:
- `User` (1) → (N) `Complaint` (as `citizen`)
- `Complaint` (1) → (1) `ComplaintClassification`
- `Complaint` (1) → (1) `ComplaintAssignment` (→ `User` as `officer`)
- `Complaint` (1) → (N) `Feedback`

---

## Function Reference

### Auth Decorators

Decorators that gate access to views. These are the core RBAC enforcement points.

| Function | Location | Description |
|----------|----------|-------------|
| `login_required(f)` | `main.py:55` | Redirects to `/Login` if `user_id` is not in the session; otherwise calls the wrapped view. |
| `admin_required(f)` | `main.py:64` | Requires a logged-in session **and** an identity number starting with `ADM`; otherwise returns `403 Access Denied`. |

### Helper Functions

| Function | Location | Description |
|----------|----------|-------------|
| `generate_identity(role_name)` | `main.py:75` | Generates the next identity number for the given role by counting existing users with the matching prefix (`CIT` / `STF` / `ADM`). |
| `send_identity_email(email, first_name, identity)` | `main.py:89` | Sends the registration-success email containing the user's identity number. Failures are logged and do not block signup. |

### Classification & Assignment Functions

| Function | Location | Description |
|----------|----------|-------------|
| `classify_complaint(title, description)` | `main.py:224` | Keyword-based classifier. Lowercases title + description and matches against keyword lists, returning `"Electricity"`, `"Water"`, `"Social"`, or `"Unclassified"`. |
| `get_next_staff_officer()` | `main.py:260` | Selects the Staff Officer with the fewest **open** (non-`Completed`) assignments; ties broken by longest-ago assignment (round-robin). Returns a `User` or `None`. |
| `assign_complaint(complaint, priority)` | `main.py:311` | Creates a `ComplaintAssignment` routed to the least-busy Staff Officer. Safe to call when no staff exist (complaint stays unassigned). |

### Route / View Functions

| Function | Route | Method | Access | Location | Description |
|----------|-------|--------|--------|----------|-------------|
| `index()` | `/` | GET | Public | `main.py:340` | Renders the landing page. |
| `login()` | `/Login` | GET, POST | Public | `main.py:344` | Authenticates by identity number + password; sets session keys (`identity`, `user_id`, `email`, `role`) and redirects by identity prefix. |
| `signup()` | `/signup` | GET, POST | Public | `main.py:375` | Registers a user, hashes the password, generates the identity number, and emails it. |
| `raise_complaint()` | `/raise_complaint` | GET, POST | `@login_required` | `main.py:419` | Creates a complaint, classifies it, stores classification, and auto-assigns it. |
| `my_complaints()` | `/my_complaints` | GET | `@login_required` | `main.py:459` | Lists the current user's complaints. |
| `citizen_dashboard()` | `/citizen/dashboard` | GET | `@login_required` | `main.py:469` | Renders the citizen dashboard. |
| `complaint_status()` | `/citizen/status` | GET | `@login_required` | `main.py:475` | Shows status of the current user's complaints. |
| `staff_dashboard()` | `/staff/dashboard` | GET | `@login_required` | `main.py:488` | Lists assignments for the logged-in Staff Officer. |
| `perform_task(assignment_id)` | `/perform_task/<int:assignment_id>` | POST | `@login_required` | `main.py:504` | Marks an assignment `Completed` (only the owning officer's assignment) and the complaint `Resolved`. |
| `admin_dashboard()` | `/admin/dashboard` | GET | `@admin_required` | `main.py:525` | Renders stats (citizen, staff, complaint, pending counts), user lists, and each officer's assignments. |
| `users()` | `/users` | GET | `@login_required` | `main.py:580` | Lists all users. |
| `audit()` | `/audit` | GET | `@admin_required` | `main.py:587` | Builds an HTML audit report of users, complaints, and classifications. |
| `delete_user(user_id)` | `/delete_user/<int:user_id>` | POST | `@admin_required` | `main.py:637` | Deletes a user; blocks self-deletion. |
| `citizen_feedback()` | `/citizen/feedback` | GET, POST | `@login_required` | `main.py:662` | Lets a citizen rate/comment on their resolved complaints (once each). |
| `staff_profile()` | `/staff/profile` | GET | `@login_required` | `main.py:725` | Shows an officer's assigned/completed/pending counts. |
| `edit_user(user_id)` | `/admin/edit_user/<int:user_id>` | GET, POST | `@admin_required` | `main.py:753` | Admin edits a user's name/email; blocks duplicate emails. |
| `admin_complaints()` | `/admin/complaints` | GET, POST | `@admin_required` | `main.py:793` | Admin views all complaints and updates status (Pending / In Progress / Resolved / Rejected); keeps assignment status in sync. |
| `admin_feedback()` | `/admin/feedback` | GET | `@admin_required` | `main.py:835` | Admin views all feedback. |
| `admin_profile()` | `/admin/profile` | GET, POST | `@admin_required` | `main.py:846` | Admin edits own profile and can change password (re-hashed with Werkzeug). |
| `logout()` | `/logout` | GET | Public | `main.py:892` | Clears the session and redirects home. |

---

## Route Map

```
/                          GET     index
/Login                     GET/POST login
/signup                    GET/POST signup
/raise_complaint           GET/POST raise_complaint
/my_complaints             GET     my_complaints
/citizen/dashboard         GET     citizen_dashboard
/citizen/status            GET     complaint_status
/citizen/feedback          GET/POST citizen_feedback
/staff/dashboard           GET     staff_dashboard
/staff/profile             GET     staff_profile
/perform_task/<id>         POST    perform_task
/admin/dashboard           GET     admin_dashboard
/admin/complaints          GET/POST admin_complaints
/admin/feedback            GET     admin_feedback
/admin/edit_user/<id>      GET/POST edit_user
/admin/profile             GET/POST admin_profile
/users                     GET     users
/audit                     GET     audit
/delete_user/<id>          POST    delete_user
/logout                    GET     logout
```

---

## Project Structure

```
classification/
├── main.py                 # App entry point: models, logic, routes
├── clear_users.py          # Utility: wipe all users + dependent records
├── requirements.txt        # Python dependencies
├── db.sqlite3              # SQLite database (auto-created)
├── LICENSE
├── README.md
├── static/
│   └── css/
│       └── auth.css        # Styling for auth pages
└── templates/              # Jinja2 templates
    ├── index.html
    ├── Login.html
    ├── signup.html
    ├── users.html
    ├── raise_complaint.html
    ├── my_complaints.html
    ├── citizen_dashboard.html
    ├── complaint_status.html
    ├── citizen_feedback.html
    ├── staff_dashboard.html
    ├── staff_profile.html
    ├── admin_dashboard.html
    ├── complaints.html
    ├── feedback.html
    ├── edit_user.html
    └── profile.html
```

---

## Utility Scripts

### `clear_users.py`

Deletes all users and dependent records in dependency order (children before parents) to avoid foreign-key errors:

```bash
python clear_users.py
```

Order: `Feedback` → `ComplaintAssignment` → `ComplaintClassification` → `Complaint` → `User`.

---

## Push Notifications - Where to Add Them

Push notifications must be triggered at the following points. Each entry names the exact function, the line, and what should be pushed to whom.

| Trigger point | Function & Location | Who gets notified | What to push |
|---------------|---------------------|-------------------|--------------|
| New complaint raised | `raise_complaint()` — after `assign_complaint(...)` at `main.py:453` | Assigned Staff Officer | New complaint assigned, with category, priority, and complaint ID |
| Auto-assignment | `assign_complaint()` — after successful commit at `main.py:333` | Assigned Staff Officer | Assignment confirmation (covers officer created after the complaint) |
| Complaint status changed by admin | `admin_complaints()` — after status update commit at `main.py:820` | Complaint's citizen | New status (`Pending` / `In Progress` / `Resolved` / `Rejected`) |
| Task completed by officer | `perform_task()` — after commit at `main.py:519` | Complaint's citizen | Complaint resolved confirmation |
| Feedback submitted | `citizen_feedback()` — after commit at `main.py:698` | Admin (and optionally assigned officer) | New feedback/rating received |
| New user registered | `signup()` — after user creation at `main.py:411` | Admin | New user registered (role + identity number) |

**Suggested implementation point:** a reusable helper function (e.g. `send_push_notification(recipient_id, title, body)`) called from the locations above — mirroring the existing `send_identity_email()` pattern at `main.py:89`. For browser push, register service workers on the dashboards (`citizen_dashboard`, `staff_dashboard`, `admin_dashboard`); for email/SMS-based fallback, reuse the Flask-Mail setup.

---

## Security System - Where to Implement It

The security system should be implemented at the following layers. Each item lists the exact function/location to harden.

### 1. RBAC Enforcement (decorators — highest priority)
- **`login_required(f)`** at `main.py:55` — currently checks only that `user_id` exists in the session. Extend to verify the session is valid and optionally check role eligibility.
- **`admin_required(f)`** at `main.py:64` — currently infers admin from the identity prefix (`ADM`). Replace prefix checks with the user's actual `role_id` so identity numbers cannot be forged. Apply `admin_required` to every admin route (see Route Map) and `login_required` to all others.
- Note: `users()` at `main.py:580` is only `@login_required` — decide if listing all users should be restricted to admin.

### 2. Authentication & Session Security
- **`login()`** at `main.py:344` — add rate limiting / account lockout against brute force, constant-time comparison handling, and CSRF protection on the POST form.
- **`signup()`** at `main.py:375` — validate all inputs (length, format, allowed role), prevent password re-use, and sanitize before hashing.
- **Session config** around `app.secret_key` at `main.py:44` — generate a strong random key and set `SESSION_COOKIE_HTTPONLY`, `SESSION_COOKIE_SAMESITE`, and `SESSION_COOKIE_SECURE`.
- **Secrets** at `main.py:35-40` (SMTP credentials) — move to environment variables / `.env`.

### 3. Authorization on Data Access (IDOR prevention)
- **`perform_task()`** at `main.py:504` — already scopes to `officer_id == session["user_id"]`; keep this pattern everywhere.
- **`delete_user(user_id)`** at `main.py:637` — verify role, block self-deletion (already done), and audit the deletion.
- **`edit_user(user_id)`** at `main.py:753` and **`admin_profile()`** at `main.py:846` — enforce that edits only touch permitted fields and the target exists.
- **`complaint_status()`** / **`my_complaints()`** at `main.py:459/475` — confirm citizens can only read their own complaints (currently filtered by `citizen_id`).

### 4. CSRF Protection (all POST routes)
Add CSRF tokens to every POST endpoint:
- `raise_complaint()` `main.py:419`
- `perform_task()` `main.py:504`
- `delete_user()` `main.py:637`
- `citizen_feedback()` `main.py:662`
- `edit_user()` `main.py:753`
- `admin_complaints()` `main.py:793`
- `admin_profile()` `main.py:846`
- `login()` `main.py:344` and `signup()` `main.py:375`

### 5. Classification Pipeline Security
- **`classify_complaint()`** at `main.py:224` — validate/sanitize input before keyword matching, and log the (input → category) pair for an audit trail.
- **`assign_complaint()`** at `main.py:311` — log assignment decisions and officer selection (from `get_next_staff_officer()` at `main.py:260`) for accountability.
- Store an audit record whenever a classification or assignment is created/modified (extend the `audit()` report at `main.py:587`).

### 6. Output / Input Sanitization
- `audit()` at `main.py:587` builds HTML with raw values — escape all user-supplied data to prevent XSS.
- All `render_template` calls that receive user data (titles, descriptions, comments, feedback) — enable auto-escaping / Jinja2 defaults and escape in templates.

### 7. General Hardening
- Disable debug mode in production — `app.run(debug=True)` at `main.py:903`.
- Wrap DB mutations in try/except with `db_session.rollback()` (pattern already used in `delete_user`, `edit_user`, `admin_complaints`, `admin_profile`).
- Add security headers (CSP, X-Frame-Options, etc.) via middleware or Flask-Talisman.

---

## License

See the `LICENSE` file in the project root.
