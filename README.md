# Complaint Registration Portal

A Flask-based complaint registration and classification system with role-based access control (RBAC). Citizens register and raise complaints, a keyword-based classifier automatically categorizes them (Electricity / Water / Social), and the system auto-assigns each complaint to the least-busy Staff Officer. System Admins manage users and can generate audit reports.

> **Note:** This project is the foundation for implementing a **security system** covering the complaint **classification** pipeline and the **RBAC** layer. The complete function reference below is provided so every function can be secured/hardened.

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
- [Security Notes for Implementation](#security-notes-for-implementation)

---

## Roles (RBAC)

The system has three roles, seeded on first run. Each user gets a unique **identity number** with a role prefix.

| Role            | Identity Prefix | Access |
|-----------------|-----------------|--------|
| Citizen         | `CIT`           | Raise complaints, view own complaints, track status, give feedback |
| Staff Officer   | `STF`           | View assigned complaints, mark tasks as completed |
| System Admin    | `ADM`           | Dashboard with stats, manage users, delete users, audit reports |

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
| `complaint_status()` | `/complaint_status` | GET | `@login_required` | `main.py:475` | Shows status of the current user's complaints. |
| `staff_dashboard()` | `/staff/dashboard` | GET | `@login_required` | `main.py:488` | Lists assignments for the logged-in Staff Officer. |
| `perform_task(assignment_id)` | `/perform_task/<int:assignment_id>` | POST | `@login_required` | `main.py:504` | Marks an assignment `Completed` (only the owning officer's assignment) and the complaint `Resolved`. |
| `admin_dashboard()` | `/admin/dashboard` | GET | `@admin_required` | `main.py:525` | Renders stats (citizen, staff, complaint, pending counts) and user lists. |
| `users()` | `/users` | GET | `@login_required` | `main.py:568` | Lists all users. |
| `audit()` | `/audit` | GET | `@admin_required` | `main.py:575` | Builds an HTML audit report of users, complaints, and classifications. |
| `delete_user(user_id)` | `/delete_user/<int:user_id>` | POST | `@admin_required` | `main.py:625` | Deletes a user; blocks self-deletion. |
| `logout()` | `/logout` | GET | Public | `main.py:650` | Clears the session and redirects home. |

---

## Route Map

```
/                    GET     index
/Login               GET/POST login
/signup              GET/POST signup
/raise_complaint     GET/POST raise_complaint
/my_complaints       GET     my_complaints
/citizen/dashboard   GET     citizen_dashboard
/complaint_status    GET     complaint_status
/staff/dashboard     GET     staff_dashboard
/perform_task/<id>   POST    perform_task
/admin/dashboard     GET     admin_dashboard
/users               GET     users
/audit               GET     audit
/delete_user/<id>    POST    delete_user
/logout              GET     logout
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
    ├── staff_dashboard.html
    ├── citizen_dashboard.html
    └── admin_dashboard.html
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

## Security Notes for Implementation

This project will be extended into a full security system around the **classification** pipeline and **RBAC**. Key areas to harden:

1. **Secrets management** — `app.secret_key`, SMTP credentials, and the Flask debug flag are hard-coded. Move to environment variables.
2. **RBAC enforcement** — Centralize role checks. `admin_required` currently checks the identity prefix; consider storing/checking `role_id` directly and auditing every route in the [Route Map](#route-map).
3. **Input validation** — `signup` and `raise_complaint` trust raw form input; validate lengths, types, and content.
4. **Classification integrity** — `classify_complaint` and `assign_complaint` run after each complaint submission; consider logging inputs/outputs and adding an audit trail for the classification pipeline.
5. **SQL injection / ORM misuse** — all queries use parameterized SQLAlchemy queries; keep it that way when extending.
6. **Session security** — configure `SESSION_COOKIE_HTTPONLY`, `SESSION_COOKIE_SAMESITE`, and `SESSION_COOKIE_SECURE`.
7. **Rate limiting & brute-force protection** — the `login` route returns raw string messages and has no throttling.
8. **CSRF protection** — `perform_task` and `delete_user` are `POST` endpoints without CSRF tokens.

---

## License

See the `LICENSE` file in the project root.
