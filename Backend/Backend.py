import os
import datetime
import json
import uuid
from functools import wraps

from flask import Flask, request, jsonify, g, url_for, redirect, current_app
from flask_sqlalchemy import SQLAlchemy
from authlib.integrations.flask_client import OAuth
import jwt
from werkzeug.security import generate_password_hash, check_password_hash
import requests
from dotenv import load_dotenv

load_dotenv()

APP_SECRET = os.environ.get("APP_SECRET", "dev-secret-change-me")
JWT_ALGO = os.environ.get("JWT_ALGO", "HS256")
JWT_EXP_HOURS = int(os.environ.get("JWT_EXP_HOURS", 72))
DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///dev.db")

GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET")
FRONTEND_URL = os.environ.get("FRONTEND_URL", "http://localhost:3000")

GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", None)

GOOGLE_PLACES_API_KEY = os.environ.get("GOOGLE_PLACES_API_KEY", None)

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = APP_SECRET

db = SQLAlchemy(app)
oauth = OAuth(app)

if GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET:
    oauth.register(
        name="google",
        client_id=GOOGLE_CLIENT_ID,
        client_secret=GOOGLE_CLIENT_SECRET,
        access_token_url="https://oauth2.googleapis.com/token",
        authorize_url="https://accounts.google.com/o/oauth2/v2/auth",
        api_base_url="https://openidconnect.googleapis.com/v1/",
        client_kwargs={"scope": "openid email profile"},
    )

# ---------- Models ----------
class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(320), unique=True, nullable=True)
    password_hash = db.Column(db.String(256), nullable=True)
    google_id = db.Column(db.String(200), unique=True, nullable=True)
    display_name = db.Column(db.String(120))
    email_verified = db.Column(db.Boolean, default=False)
    role = db.Column(db.String(32), default="user")
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class Assessment(db.Model):
    __tablename__ = "assessments"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    type = db.Column(db.String(80), nullable=False)
    answers = db.Column(db.JSON, nullable=False)
    score = db.Column(db.Float, nullable=False)
    confidence = db.Column(db.Float, nullable=False)
    interpretation = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class Report(db.Model):
    __tablename__ = "reports"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    conversation_id = db.Column(db.String(36), db.ForeignKey("conversations.id"), nullable=True)
    anchor_message_id = db.Column(db.Integer, db.ForeignKey("messages.id"), nullable=True)
    assessment_id = db.Column(db.Integer, db.ForeignKey("assessments.id"), nullable=True)
    report_url = db.Column(db.Text, nullable=True)  # link to PDF / file in storage
    format = db.Column(db.String(16), default="pdf")
    version = db.Column(db.Integer, default=1)
    generated_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    user = db.relationship("User", backref="reports", lazy=True)
    conversation = db.relationship("Conversation", backref="reports", lazy=True)
    assessment = db.relationship("Assessment", backref="reports", lazy=True)

class Conversation(db.Model):
    __tablename__ = "conversations"
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    title = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    messages = db.relationship("Message", backref="conversation", lazy=True)

class Message(db.Model):
    __tablename__ = "messages"
    id = db.Column(db.Integer, primary_key=True)
    conversation_id = db.Column(db.String(36), db.ForeignKey("conversations.id"))
    sender = db.Column(db.String(32))  # 'user' / 'assistant' / 'system'
    content = db.Column(db.Text)
    llm_meta = db.Column(db.JSON)  # model name, tokens, etc.
    report_id = db.Column(db.Integer, db.ForeignKey("reports.id"), nullable=True)  # new
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class Summary(db.Model):
    __tablename__ = "summaries"
    id = db.Column(db.Integer, primary_key=True)
    conversation_id = db.Column(db.String(36), db.ForeignKey("conversations.id"), unique=True)
    summary_text = db.Column(db.Text)
    version = db.Column(db.Integer, default=1)
    last_updated_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

class LearnContent(db.Model):
    __tablename__ = "learn_content"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(300))
    type = db.Column(db.String(32))  
    url = db.Column(db.Text)
    summary = db.Column(db.Text)
    tags = db.Column(db.JSON)  
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class Consultant(db.Model):
    __tablename__ = "consultants"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200))
    speciality = db.Column(db.String(100))
    phone = db.Column(db.String(50))
    place_id = db.Column(db.String(200))
    address = db.Column(db.Text)
    lat = db.Column(db.Float)
    lng = db.Column(db.Float)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class Contact(db.Model):
    __tablename__ = "contacts"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    name = db.Column(db.String(200))
    email = db.Column(db.String(320))
    message = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

# ---------- Utilities: JWT / Auth ----------
def create_jwt(user_id: int):
    payload = {
        "sub": user_id,
        "iat": datetime.datetime.utcnow().timestamp(),
        "exp": (datetime.datetime.utcnow() + datetime.timedelta(hours=JWT_EXP_HOURS)).timestamp()
    }
    token = jwt.encode(payload, APP_SECRET, algorithm=JWT_ALGO)
    if isinstance(token, bytes):
        token = token.decode("utf-8")
    return token

def decode_jwt(token: str):
    try:
        return jwt.decode(token, APP_SECRET, algorithms=[JWT_ALGO])
    except Exception:
        return None

def auth_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "Missing token"}), 401
        token = auth.split(" ", 1)[1]
        payload = decode_jwt(token)
        if not payload:
            return jsonify({"error": "Invalid token"}), 401
        user = User.query.get(payload["sub"])
        if not user:
            return jsonify({"error": "User not found"}), 401
        g.current_user = user
        return f(*args, **kwargs)
    return wrapper

# ---------- Routes: Auth ----------
@app.route("/auth/signup", methods=["POST"])
def signup():
    data = request.json or {}
    email = data.get("email")
    password = data.get("password")
    name = data.get("display_name")
    if not email or not password:
        return jsonify({"error": "email and password required"}), 400
    if User.query.filter_by(email=email).first():
        return jsonify({"error": "email already registered"}), 400
    user = User(email=email, password_hash=generate_password_hash(password), display_name=name, email_verified=False)
    db.session.add(user)
    db.session.commit()
    token = create_jwt(user.id)
    return jsonify({"token": token, "user": {"id": user.id, "email": user.email, "display_name": user.display_name}}), 201

@app.route("/auth/login", methods=["POST"])
def login():
    data = request.json or {}
    email = data.get("email")
    password = data.get("password")
    if not email or not password:
        return jsonify({"error": "email and password required"}), 400
    user = User.query.filter_by(email=email).first()
    if not user or not user.password_hash or not check_password_hash(user.password_hash, password):
        return jsonify({"error": "invalid credentials"}), 401
    token = create_jwt(user.id)
    return jsonify({"token": token, "user": {"id": user.id, "email": user.email, "display_name": user.display_name}})

@app.route("/auth/me", methods=["GET"])
@auth_required
def me():
    u = g.current_user
    return jsonify({"id": u.id, "email": u.email, "display_name": u.display_name, "role": u.role})