from flask import Flask, render_template, request, redirect, session, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from functools import wraps

import sqlalchemy
from sqlalchemy import (
    create_engine,
    Column,
    Integer,
    String,
    Text,
    Float,
    ForeignKey,
    DateTime,
    func
)

from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import relationship

from datetime import datetime

import os

Base = declarative_base()

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
engine = create_engine(f"sqlite:///{os.path.join(BASE_DIR, 'db.sqlite3')}")

app = Flask(__name__)

app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USERNAME"] = "shamikshab20228042@gmail.com"
app.config["MAIL_PASSWORD"] = "xkzy uztm qjcs hmnz"
app.config["MAIL_DEFAULT_SENDER"] = "shamikshab20228042@gmail.com"

mail = Mail(app)

app.secret_key = "your_super_secret_key_here"
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{os.path.join(BASE_DIR, 'db.sqlite3')}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

SessionLocal = sessionmaker(bind=engine)
db_session = SessionLocal()


# ---------------------------------------------------------
# Helper: login-required decorator (avoids repeating checks)
# ---------------------------------------------------------
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect("/Login")
        return f(*args, **kwargs)
    return wrapper


def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect("/Login")
        if not session.get("identity", "").startswith("ADM"):
            return "Access Denied", 403
        return f(*args, **kwargs)
    return wrapper


def generate_identity(role_name):
    prefix = {
        "Citizen": "CIT",
        "Staff Officer": "STF",
        "System Admin": "ADM"
    }[role_name]

    count = db_session.query(User).filter(
        User.identity_number.like(f"{prefix}%")
    ).count()

    return f"{prefix}{count + 1:06d}"


def send_identity_email(email, first_name, identity):
    msg = Message(
        subject="Complaint Management System - Registration Successful",
        recipients=[email]
    )

    msg.html = f"""
    <h2>Welcome, {first_name}!</h2>
    <p>Your account has been created successfully.</p>
    <h3>Your Identity Number</h3>
    <h1>{identity}</h1>
    <p>
    Please keep this Identity Number safe.
    You will use it while logging in to the Complaint Management System.
    </p>
    <br>
    <p>
    Regards,<br>
    Complaint Management Team
    </p>
    """

    try:
        mail.send(msg)
        print(f"[INFO] Identity email sent successfully to {email}")
    except Exception as e:
        # Don't let a mail failure break signup
        print(f"[ERROR] Failed to send identity email to {email}: {type(e).__name__}: {e}")


# ---------------------------------------------------------
# Models
# ---------------------------------------------------------
class Role(Base):
    __tablename__ = "roles"

    id = Column(Integer, primary_key=True)
    role_name = Column(String(50), unique=True, nullable=False)

    users = relationship("User", back_populates="role")


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    identity_number = Column(String(20), unique=True, nullable=False)
    first_name = Column(String(100), nullable=False)
    last_name = Column(String(100), nullable=False)
    email = Column(String(120), unique=True, nullable=False)
    password = Column(String(255), nullable=False)
    role_id = Column(Integer, ForeignKey("roles.id"))
    created_at = Column(DateTime, default=datetime.utcnow)

    role = relationship("Role", back_populates="users")


class Complaint(Base):
    __tablename__ = "complaints"

    id = Column(Integer, primary_key=True)
    title = Column(String(200), nullable=False)
    description = Column(Text, nullable=False)
    location = Column(String(255))
    status = Column(String(50), default="Pending")
    citizen_id = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime, default=datetime.utcnow)

    citizen = relationship("User")
    classification = relationship(
        "ComplaintClassification",
        back_populates="complaint",
        uselist=False
    )
    assignment = relationship(
        "ComplaintAssignment",
        back_populates="complaint",
        uselist=False
    )


class ComplaintClassification(Base):
    __tablename__ = "complaint_classification"

    id = Column(Integer, primary_key=True)
    complaint_id = Column(Integer, ForeignKey("complaints.id"), unique=True)
    category = Column(String(100))
    priority = Column(String(50))
    confidence = Column(Float)
    classified_at = Column(DateTime, default=datetime.utcnow)

    complaint = relationship("Complaint", back_populates="classification")


class ComplaintAssignment(Base):
    __tablename__ = "complaint_assignment"

    id = Column(Integer, primary_key=True)
    complaint_id = Column(Integer, ForeignKey("complaints.id"), unique=True)
    officer_id = Column(Integer, ForeignKey("users.id"))
    priority = Column(String(50), default="Medium")
    status = Column(String(50), default="Pending")
    assigned_at = Column(DateTime, default=datetime.utcnow)

    complaint = relationship("Complaint", back_populates="assignment")
    officer = relationship("User")


class Feedback(Base):
    __tablename__ = "feedback"

    id = Column(Integer, primary_key=True)
    complaint_id = Column(Integer, ForeignKey("complaints.id"))
    citizen_id = Column(Integer, ForeignKey("users.id"))
    rating = Column(Integer)
    comments = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)

    complaint = relationship("Complaint")
    citizen = relationship("User")


Base.metadata.create_all(engine)

# Seed roles if they don't exist
if db_session.query(Role).count() == 0:
    db_session.add_all([
        Role(role_name="Citizen"),
        Role(role_name="Staff Officer"),
        Role(role_name="System Admin")
    ])
    db_session.commit()
    print("Default roles created.")


def classify_complaint(title, description):
    text = (title + " " + description).lower()

    electricity_keywords = [
        "electricity", "power", "current", "transformer", "wire",
        "voltage", "eb", "electric", "street light", "blackout"
    ]

    water_keywords = [
        "water", "pipe", "drain", "drainage", "sewage", "leak",
        "tap", "tank", "bore", "overflow"
    ]

    social_keywords = [
        "road", "garbage", "waste", "hospital", "school", "crime",
        "noise", "park", "traffic", "encroachment"
    ]

    for word in electricity_keywords:
        if word in text:
            return "Electricity"

    for word in water_keywords:
        if word in text:
            return "Water"

    for word in social_keywords:
        if word in text:
            return "Social"

    return "Unclassified"


# ---------------------------------------------------------
# Auto-assignment: least-busy staff officer, round-robin on ties
# ---------------------------------------------------------
def get_next_staff_officer():
    """
    Picks the Staff Officer with the fewest OPEN (non-closed) assignments.
    Ties are broken by whoever was assigned longest ago (round-robin),
    so load spreads evenly across officers over time.
    Returns a User instance, or None if no Staff Officer accounts exist.
    """
    staff_role = db_session.query(Role).filter_by(role_name="Staff Officer").first()
    if not staff_role:
        return None

    staff_officers = (
        db_session.query(User)
        .filter(User.role_id == staff_role.id)
        .all()
    )

    if not staff_officers:
        return None

    # Count only open assignments per officer, so completed/closed work
    # doesn't keep making an officer look "busy" forever.
    open_counts = dict(
        db_session.query(
            ComplaintAssignment.officer_id,
            func.count(ComplaintAssignment.id)
        )
        .filter(ComplaintAssignment.status != "Completed")
        .group_by(ComplaintAssignment.officer_id)
        .all()
    )

    # Last-assigned timestamp per officer, for round-robin tiebreaking.
    last_assigned = dict(
        db_session.query(
            ComplaintAssignment.officer_id,
            func.max(ComplaintAssignment.assigned_at)
        )
        .group_by(ComplaintAssignment.officer_id)
        .all()
    )

    def sort_key(officer):
        load = open_counts.get(officer.id, 0)
        last_time = last_assigned.get(officer.id) or datetime.min
        return (load, last_time)

    staff_officers.sort(key=sort_key)
    return staff_officers[0]


def assign_complaint(complaint, priority):
    """
    Creates a ComplaintAssignment for the given complaint, routed to the
    least-busy Staff Officer. Safe to call even if no staff exist yet
    (the complaint just stays unassigned until one signs up).
    """
    officer = get_next_staff_officer()
    if not officer:
        print("[WARN] No Staff Officer available to assign complaint to.")
        return None

    assignment = ComplaintAssignment(
        complaint_id=complaint.id,
        officer_id=officer.id,
        priority=priority,
        status="Pending"
    )

    db_session.add(assignment)
    db_session.commit()

    print(f"[INFO] Complaint {complaint.id} auto-assigned to {officer.identity_number}")
    return assignment


# ---------------------------------------------------------
# Routes
# ---------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/Login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("Login.html")

    identity = (request.form.get("identity_number") or "").strip()
    password = request.form.get("password") or ""

    user = db_session.query(User).filter_by(identity_number=identity).first()

    if not user:
        return "Invalid Identity Number"

    if not check_password_hash(user.password, password):
        return "Invalid Password"

    session["identity"] = user.identity_number
    session["user_id"] = user.id
    session["email"] = user.email
    session["role"] = user.role.role_name

    if identity.startswith("ADM"):
        return redirect("/admin/dashboard")
    elif identity.startswith("STF"):
        return redirect("/staff/dashboard")
    elif identity.startswith("CIT"):
        return redirect("/citizen/dashboard")
    else:
        return "Invalid Identity Number"


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "GET":
        return render_template("signup.html")

    first_name = request.form.get("first_name")
    last_name = request.form.get("last_name")
    email = request.form.get("email")
    password = request.form.get("password")
    confirm_password = request.form.get("confirm_password")
    role_name = request.form.get("role")

    if password != confirm_password:
        return "Passwords do not match"

    existing_user = db_session.query(User).filter_by(email=email).first()
    if existing_user:
        return "Email already registered"

    role = db_session.query(Role).filter_by(role_name=role_name).first()
    if not role:
        return "Invalid Role"

    identity = generate_identity(role_name)
    hashed_password = generate_password_hash(password)

    new_user = User(
        identity_number=identity,
        first_name=first_name,
        last_name=last_name,
        email=email,
        password=hashed_password,
        role_id=role.id
    )

    db_session.add(new_user)
    db_session.commit()

    send_identity_email(email=email, first_name=first_name, identity=identity)

    flash(f"Registration successful! Your Identity Number is {identity}", "success")
    return redirect("/Login")


@app.route("/raise_complaint", methods=["GET", "POST"])
@login_required
def raise_complaint():
    if request.method == "GET":
        return render_template("raise_complaint.html")

    title = request.form.get("title")
    description = request.form.get("description")
    location = request.form.get("location")

    complaint = Complaint(
        title=title,
        description=description,
        location=location,
        citizen_id=session["user_id"],
        status="Pending"
    )

    db_session.add(complaint)
    db_session.commit()

    category = classify_complaint(complaint.title, complaint.description)

    classification = ComplaintClassification(
        complaint_id=complaint.id,
        category=category,
        priority="Medium",
        confidence=1.0
    )

    db_session.add(classification)
    db_session.commit()

    # Auto-assign to the least-busy Staff Officer (round-robin on ties)
    assign_complaint(complaint, priority=classification.priority)

    flash("Complaint submitted successfully!", "success")
    return redirect("/my_complaints")


@app.route("/my_complaints")
@login_required
def my_complaints():
    complaints = db_session.query(Complaint).filter_by(
        citizen_id=session["user_id"]
    ).order_by(Complaint.created_at.desc()).all()

    return render_template("my_complaints.html", complaints=complaints)


@app.route("/citizen/dashboard")
@login_required
def citizen_dashboard():
    return render_template("citizen_dashboard.html")


@app.route("/citizen/status")
@login_required
def complaint_status():
    complaints = (
        db_session.query(Complaint)
        .filter_by(citizen_id=session["user_id"])
        .order_by(Complaint.created_at.desc())
        .all()
    )

    return render_template("complaint_status.html", complaints=complaints)


@app.route("/staff/dashboard")
@login_required
def staff_dashboard():
    assignments = (
        db_session.query(ComplaintAssignment)
        .filter_by(officer_id=session["user_id"])
        .order_by(ComplaintAssignment.assigned_at.desc())
        .all()
    )

    return render_template(
        "staff_dashboard.html",
        assignments=assignments
    )


@app.route("/perform_task/<int:assignment_id>", methods=["POST"])
@login_required
def perform_task(assignment_id):
    assignment = (
        db_session.query(ComplaintAssignment)
        .filter_by(id=assignment_id, officer_id=session["user_id"])
        .first()
    )

    if not assignment:
        flash("Assignment not found.", "error")
        return redirect("/staff/dashboard")

    assignment.status = "Completed"
    assignment.complaint.status = "Resolved"
    db_session.commit()

    flash("Task marked as completed.", "success")
    return redirect("/staff/dashboard")


@app.route("/admin/dashboard")
@admin_required
def admin_dashboard():
    citizen_count = (
        db_session.query(User).join(Role)
        .filter(Role.role_name == "Citizen").count()
    )

    staff_count = (
        db_session.query(User).join(Role)
        .filter(Role.role_name == "Staff Officer").count()
    )

    complaint_count = db_session.query(Complaint).count()

    pending_count = (
        db_session.query(Complaint)
        .filter(Complaint.status == "Pending").count()
    )

    citizens = (
        db_session.query(User).join(Role)
        .filter(Role.role_name == "Citizen")
        .order_by(User.first_name).all()
    )

    staffs = (
        db_session.query(User).join(Role)
        .filter(Role.role_name == "Staff Officer")
        .order_by(User.first_name).all()
    )

    # Build a mapping of staff_id -> list of their assignments, so the
    # template can show each officer's assigned work inline.
    staff_assignments = {}
    for staff in staffs:
        staff_assignments[staff.id] = (
            db_session.query(ComplaintAssignment)
            .filter_by(officer_id=staff.id)
            .order_by(ComplaintAssignment.assigned_at.desc())
            .all()
        )

    return render_template(
        "admin_dashboard.html",
        citizen_count=citizen_count,
        staff_count=staff_count,
        complaint_count=complaint_count,
        pending_count=pending_count,
        citizens=citizens,
        staffs=staffs,
        staff_assignments=staff_assignments
    )


@app.route("/users")
@login_required
def users():
    all_users = db_session.query(User).all()
    return render_template("users.html", users=all_users)


@app.route("/audit")
@admin_required
def audit():
    all_users = db_session.query(User).all()
    all_complaints = db_session.query(Complaint).all()
    all_classifications = db_session.query(ComplaintClassification).all()

    # Still log to console for debugging
    print("\n===== USERS =====")
    for u in all_users:
        print(u.identity_number, u.first_name, u.email, u.role.role_name)

    print("\n===== COMPLAINTS =====")
    for c in all_complaints:
        print(c.id, c.title, c.location, c.status, c.citizen_id)

    print("\n===== CLASSIFICATIONS =====")
    for cls in all_classifications:
        print(cls.complaint_id, cls.category, cls.priority)

    # Build a simple readable HTML report instead of a blank "Audit complete."
    html = ["<h1>Audit Report</h1>"]

    html.append("<h2>Users</h2><table border='1' cellpadding='6'>")
    html.append("<tr><th>Identity</th><th>Name</th><th>Email</th><th>Role</th></tr>")
    for u in all_users:
        html.append(
            f"<tr><td>{u.identity_number}</td><td>{u.first_name} {u.last_name}</td>"
            f"<td>{u.email}</td><td>{u.role.role_name}</td></tr>"
        )
    html.append("</table>")

    html.append("<h2>Complaints</h2><table border='1' cellpadding='6'>")
    html.append("<tr><th>ID</th><th>Title</th><th>Location</th><th>Status</th><th>Citizen ID</th></tr>")
    for c in all_complaints:
        html.append(
            f"<tr><td>{c.id}</td><td>{c.title}</td><td>{c.location}</td>"
            f"<td>{c.status}</td><td>{c.citizen_id}</td></tr>"
        )
    html.append("</table>")

    html.append("<h2>Classifications</h2><table border='1' cellpadding='6'>")
    html.append("<tr><th>Complaint ID</th><th>Category</th><th>Priority</th></tr>")
    for cls in all_classifications:
        html.append(f"<tr><td>{cls.complaint_id}</td><td>{cls.category}</td><td>{cls.priority}</td></tr>")
    html.append("</table>")

    return "".join(html)


@app.route("/delete_user/<int:user_id>", methods=["POST"])
@admin_required
def delete_user(user_id):
    user = db_session.query(User).filter_by(id=user_id).first()

    if not user:
        flash("User not found", "error")
        return redirect("/users")

    # Prevent an admin from deleting their own account by accident
    if user.id == session.get("user_id"):
        flash("You cannot delete your own account while logged in.", "error")
        return redirect("/users")

    try:
        db_session.delete(user)
        db_session.commit()
        flash(f"User {user.identity_number} deleted successfully.", "success")
    except Exception as e:
        db_session.rollback()
        flash(f"Could not delete user: {e}", "error")

    return redirect("/users")


@app.route("/citizen/feedback", methods=["GET", "POST"])
@login_required
def citizen_feedback():
    if request.method == "POST":
        complaint_id = request.form.get("complaint_id")
        rating = request.form.get("rating")
        comments = request.form.get("comments")

        complaint = (
            db_session.query(Complaint)
            .filter_by(id=complaint_id, citizen_id=session["user_id"], status="Resolved")
            .first()
        )

        if not complaint:
            flash("Invalid or unresolved complaint selected.", "error")
            return redirect("/citizen/feedback")

        already_reviewed = (
            db_session.query(Feedback)
            .filter_by(complaint_id=complaint.id, citizen_id=session["user_id"])
            .first()
        )

        if already_reviewed:
            flash("You've already submitted feedback for this complaint.", "error")
            return redirect("/citizen/feedback")

        feedback = Feedback(
            complaint_id=complaint.id,
            citizen_id=session["user_id"],
            rating=int(rating) if rating else None,
            comments=comments
        )

        db_session.add(feedback)
        db_session.commit()

        flash("Thank you! Your feedback has been submitted.", "success")
        return redirect("/citizen/feedback")

    # Resolved complaints belonging to this citizen that don't already have feedback
    already_reviewed_ids = [
        row[0] for row in
        db_session.query(Feedback.complaint_id)
        .filter_by(citizen_id=session["user_id"])
        .all()
    ]

    resolvable_complaints = (
        db_session.query(Complaint)
        .filter(
            Complaint.citizen_id == session["user_id"],
            Complaint.status == "Resolved",
            ~Complaint.id.in_(already_reviewed_ids) if already_reviewed_ids else True
        )
        .order_by(Complaint.created_at.desc())
        .all()
    )

    return render_template("citizen_feedback.html", complaints=resolvable_complaints)


@app.route("/staff/profile")
@login_required
def staff_profile():
    user = db_session.query(User).filter_by(id=session["user_id"]).first()

    total_assigned = (
        db_session.query(ComplaintAssignment)
        .filter_by(officer_id=user.id)
        .count()
    )

    completed = (
        db_session.query(ComplaintAssignment)
        .filter_by(officer_id=user.id, status="Completed")
        .count()
    )

    pending = total_assigned - completed

    return render_template(
        "staff_profile.html",
        user=user,
        total_assigned=total_assigned,
        completed=completed,
        pending=pending
    )


@app.route("/admin/edit_user/<int:user_id>", methods=["GET", "POST"])
@admin_required
def edit_user(user_id):
    user = db_session.query(User).filter_by(id=user_id).first()

    if not user:
        flash("User not found.", "error")
        return redirect("/admin/dashboard")

    if request.method == "POST":
        first_name = request.form.get("first_name")
        last_name = request.form.get("last_name")
        email = request.form.get("email")

        # Prevent duplicate emails across OTHER users
        existing = (
            db_session.query(User)
            .filter(User.email == email, User.id != user.id)
            .first()
        )

        if existing:
            flash("That email is already in use by another user.", "error")
            return redirect(f"/admin/edit_user/{user.id}")

        user.first_name = first_name
        user.last_name = last_name
        user.email = email

        try:
            db_session.commit()
            flash(f"User {user.identity_number} updated successfully.", "success")
        except Exception as e:
            db_session.rollback()
            flash(f"Could not update user: {e}", "error")

        return redirect("/admin/dashboard")

    return render_template("edit_user.html", user=user)

@app.route("/admin/complaints", methods=["GET", "POST"])
@admin_required
def admin_complaints():
    if request.method == "POST":
        complaint_id = request.form.get("complaint_id")
        new_status = request.form.get("status")

        valid_statuses = ["Pending", "In Progress", "Resolved", "Rejected"]

        complaint = db_session.query(Complaint).filter_by(id=complaint_id).first()

        if not complaint:
            flash("Complaint not found.", "error")
        elif new_status not in valid_statuses:
            flash("Invalid status value.", "error")
        else:
            complaint.status = new_status

            # Keep the linked assignment status roughly in sync
            if complaint.assignment:
                if new_status == "Resolved":
                    complaint.assignment.status = "Completed"
                elif new_status in ("Pending", "In Progress"):
                    complaint.assignment.status = "Pending"

            try:
                db_session.commit()
                flash(f"Complaint #{complaint.id} status updated to '{new_status}'.", "success")
            except Exception as e:
                db_session.rollback()
                flash(f"Could not update status: {e}", "error")

        return redirect("/admin/complaints")

    complaints = (
        db_session.query(Complaint)
        .order_by(Complaint.created_at.desc())
        .all()
    )

    return render_template("complaints.html", complaints=complaints)

@app.route("/admin/feedback")
@admin_required
def admin_feedback():
    feedback_list = (
        db_session.query(Feedback)
        .order_by(Feedback.created_at.desc())
        .all()
    )

    return render_template("feedback.html", feedback_list=feedback_list)

@app.route("/admin/profile", methods=["GET", "POST"])
@admin_required
def admin_profile():
    user = db_session.query(User).filter_by(id=session["user_id"]).first()

    if request.method == "POST":
        first_name = request.form.get("first_name")
        last_name = request.form.get("last_name")
        email = request.form.get("email")
        new_password = request.form.get("new_password")
        confirm_password = request.form.get("confirm_password")

        # Prevent duplicate emails across OTHER users
        existing = (
            db_session.query(User)
            .filter(User.email == email, User.id != user.id)
            .first()
        )

        if existing:
            flash("That email is already in use by another user.", "error")
            return redirect("/admin/profile")

        user.first_name = first_name
        user.last_name = last_name
        user.email = email

        if new_password:
            if new_password != confirm_password:
                flash("New passwords do not match.", "error")
                return redirect("/admin/profile")
            user.password = generate_password_hash(new_password)

        try:
            db_session.commit()
            session["email"] = user.email  # keep session in sync
            flash("Profile updated successfully.", "success")
        except Exception as e:
            db_session.rollback()
            flash(f"Could not update profile: {e}", "error")

        return redirect("/admin/profile")

    return render_template("profile.html", user=user)


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")




if __name__ == "__main__":
    print("Running file:", os.path.abspath(__file__))
    print(app.url_map)
    app.run(debug=True)