from flask import Flask, render_template, request, redirect, session, url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from flask import Flask, render_template, request, redirect, session, flash


import sqlalchemy
from sqlalchemy import (
    create_engine,
    Column,
    Integer,
    String,
    Text,
    Float,
    ForeignKey,
    DateTime
)

from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import relationship

from datetime import datetime


import sqlite3 
import os


Base = declarative_base()

engine = create_engine('sqlite:///db.sqlite3')



app = Flask(__name__)

app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USERNAME"] = "shamikshab20228042@gmail.com"
app.config["MAIL_PASSWORD"] = "pipi xxtr vfac zyds"
app.config["MAIL_DEFAULT_SENDER"] = "yourgmail@gmail.com"

mail = Mail(app)


app.secret_key = "your_super_secret_key_here"
app.config['SQLALCHEMY_DATABASE_URI'] ='sqlite:///db.sqlite3'
app.config['SQALCHEMY_TRACK_MODIFICAIIONS'] = False


SessionLocal=sessionmaker(bind=engine)
db_session=SessionLocal()

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

    mail.send(msg)


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


class ComplaintClassification(Base):
    __tablename__ = "complaint_classification"

    id = Column(Integer, primary_key=True)

    complaint_id = Column(
        Integer,
        ForeignKey("complaints.id"),
        unique=True
    )

    category = Column(String(100))

    priority = Column(String(50))

    confidence = Column(Float)

    classified_at = Column(
        DateTime,
        default=datetime.utcnow
    )

    complaint = relationship(
        "Complaint",
        back_populates="classification"
    )

class ComplaintAssignment(Base):
    __tablename__ = "complaint_assignment"

    id = Column(Integer, primary_key=True)

    complaint_id = Column(Integer,
                          ForeignKey("complaints.id"))

    officer_id = Column(Integer,
                        ForeignKey("users.id"))

    assigned_at = Column(DateTime,
                         default=datetime.utcnow)

    complaint = relationship("Complaint")

    officer = relationship("User")

class Feedback(Base):
    __tablename__ = "feedback"

    id = Column(Integer, primary_key=True)

    complaint_id = Column(Integer,
                          ForeignKey("complaints.id"))

    citizen_id = Column(Integer,
                        ForeignKey("users.id"))

    rating = Column(Integer)

    comments = Column(Text)

    created_at = Column(DateTime,
                        default=datetime.utcnow)

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
        "electricity",
        "power",
        "current",
        "transformer",
        "wire",
        "voltage",
        "eb",
        "electric",
        "street light",
        "blackout"
    ]

    water_keywords = [
        "water",
        "pipe",
        "drain",
        "drainage",
        "sewage",
        "leak",
        "tap",
        "tank",
        "bore",
        "overflow"
    ]

    social_keywords = [
        "road",
        "garbage",
        "waste",
        "hospital",
        "school",
        "crime",
        "noise",
        "park",
        "traffic",
        "encroachment"
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

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/Login", methods=["GET", "POST"])
def login():

    if request.method == "GET":
        return render_template("Login.html")

    identity = request.form.get("identity_number")
    password = request.form.get("password")

    # Find the user by identity number
    user = db_session.query(User).filter_by(
        identity_number=identity
    ).first()

    if not user:
        return "Invalid Identity Number"

    if not check_password_hash(user.password, password):
        return "Invalid Password"

    # Store session values
    session["identity"] = user.identity_number
    session["user_id"] = user.id
    session["email"] = user.email
    session["role"] = user.role.role_name

    # Decide dashboard based on identity prefix
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
    role_name = request.form.get("role")      # Citizen / Staff Officer / System Admin

    if password != confirm_password:
        return "Passwords do not match"

    # Check if email already exists
    existing_user = db_session.query(User).filter_by(email=email).first()

    if existing_user:
        return "Email already registered"

    # Get role from Roles table
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

    send_identity_email(
        email=email,
        first_name=first_name,
        identity=identity
    )

    print(f"""
        Registration Successful!<br><br>

        Your Identity Number is:

        <b>{identity}</b>

        <br><br>

        Please use this ID to log in.
        """)

    
    return redirect("/Login")

@app.route("/raise_complaint", methods=["GET", "POST"])
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
        citizen_id=session["user_id"],     # Logged in citizen
        status="Pending"
    )

    db_session.add(complaint)
    db_session.commit()

    category = classify_complaint(
    complaint.title,
    complaint.description
    )

    classification = ComplaintClassification(
    complaint_id=complaint.id,
    category=category,
    priority="Medium",
    confidence=1.0
    )

    db_session.add(classification)
    db_session.commit()

    flash("Complaint submitted successfully!", "success")
    return redirect("/my_complaints")

@app.route("/my_complaints")
def my_complaints():

    complaints = db_session.query(Complaint).filter_by(
        citizen_id=session["user_id"]
    ).order_by(Complaint.created_at.desc()).all()

    return render_template(
        "my_complaints.html",
        complaints=complaints
    )

@app.route("/citizen/dashboard")
def citizen_dashboard():

    # Optional: Prevent access if not logged in
    if "user_id" not in session:
        return redirect("/Login")

    return render_template("citizen_dashboard.html")

@app.route("/complaint_status")
def complaint_status():

    # User must be logged in
    if "user_id" not in session:
        return redirect("/Login")

    complaints = (
        db_session.query(Complaint)
        .filter_by(citizen_id=session["user_id"])
        .order_by(Complaint.created_at.desc())
        .all()
    )

    return render_template(
        "complaint_status.html",
        complaints=complaints
    )

@app.route("/staff/dashboard")
def staff_dashboard():

    if "user_id" not in session:
        return redirect("/Login")

    electricity = (
        db_session.query(ComplaintClassification)
        .filter_by(category="Electricity")
        .all()
    )

    water = (
        db_session.query(ComplaintClassification)
        .filter_by(category="Water")
        .all()
    )

    social = (
        db_session.query(ComplaintClassification)
        .filter_by(category="Social")
        .all()
    )

    return render_template(
        "staff_dashboard.html",
        electricity=electricity,
        water=water,
        social=social
    )
    

@app.route("/users")
def users():
    users = db_session.query(User).all()
    return render_template("users.html", users=users)

@app.route("/index")
def logout():
    session.clear()
    return redirect("/")

if __name__ == "__main__":
    app.run(debug=True)