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
        server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
        client_kwargs={
            "scope": "openid email profile"
        },
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

# ---------- Scoring functions (MVP) ----------
def score_asrs6(answers: dict):
    keys = [f"q{i}" for i in range(1, 7)]
    s = sum(int(answers.get(k, 0)) for k in keys)
    conf = min(1.0, max(0.05, (s / 24) * 1.2))
    if s >= 17:
        interp = "High number of ADHD-like symptoms. Consider formal evaluation."
    elif s >= 11:
        interp = "Moderate ADHD-like symptoms."
    else:
        interp = "Low ADHD-like symptoms according to ASRS-6."
    return s, conf, interp

def score_phq2(answers: dict):
    s = int(answers.get("q1", 0)) + int(answers.get("q2", 0))
    conf = min(1.0, max(0.05, (s / 6) * 1.1))
    if s >= 3:
        interp = "Positive screen for depressive symptoms. Consider full PHQ-9 or clinical consult."
    else:
        interp = "Low depressive symptomatology on PHQ-2."
    return s, conf, interp

SCORE_FUNCS = {
    "ADHD_ASRS6": score_asrs6,
    "PHQ2": score_phq2
}

# ---------- LLM (Gemini) stub: replace with real call ----------
def call_gemini(prompt: str, max_tokens: int = 512) -> dict:
    """
    Replace this stub with your actual Gemini API call.
    Expected return: dict with keys {'response': str, 'summary': str, 'meta': {...}}
    For now this returns a mocked helpful reply and summary.
    """
    # Example: use requests to call Gemini REST endpoint or Google client
    # See Gemini docs and authentication; do not call from frontend.
    mocked_response = "I hear you. Try short focused sessions, externalize reminders, and seek professional help if interference continues. This is a screening tool and not a clinical diagnosis. For concerns, consult a professional."
    mocked_summary = "User reports concentration problems and repetitive checking; recommended short focus sessions, external reminders, and clinician consult if persistent."
    return {"response": mocked_response, "summary": mocked_summary, "meta": {"report_flag": False, "injection_detected": False}}

# ---------- Prompt-injection heuristic ----------
INJECTION_PATTERNS = [
    "ignore previous", "ignore all previous", "forget previous", "disregard prior",
    "override instructions", "do not follow", "from now on you are", "run this code",
    "execute the following", "<script", "erase history", "delete this message"
]
def is_injection(text: str) -> bool:
    t = (text or "").lower()
    for p in INJECTION_PATTERNS:
        if p in t:
            return True
    return False

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

# Google OAuth endpoints (if configured)
@app.route("/auth/google/login")
def google_login():
    if "google" not in oauth._clients:
        return jsonify({"error": "Google OAuth not configured"}), 400
    redirect_uri = url_for("google_callback", _external=True)
    return oauth.google.authorize_redirect(redirect_uri)

@app.route("/auth/google/callback")
def google_callback():
    if "google" not in oauth._clients:
        return jsonify({"error": "Google OAuth not configured"}), 400
    token = oauth.google.authorize_access_token()
    if not token:
        return jsonify({"error": "failed to get token"}), 400
    userinfo = oauth.google.userinfo()
    if not userinfo:
        userinfo = oauth.google.get("userinfo").json()
    google_sub = userinfo.get("sub")
    email = userinfo.get("email")
    email_verified = userinfo.get("email_verified", False)
    name = userinfo.get("name") or userinfo.get("given_name")
    user = None
    if google_sub:
        user = User.query.filter_by(google_id=google_sub).first()
    if not user and email:
        existing = User.query.filter_by(email=email).first()
        if existing:
            if email_verified:
                existing.google_id = google_sub
                existing.email_verified = True
                if not existing.display_name and name:
                    existing.display_name = name
                db.session.add(existing)
                db.session.commit()
                user = existing
            else:
                return jsonify({"error": "link_required", "message": "Account exists with this email; sign in to link."}), 200
    if not user:
        user = User(email=email, google_id=google_sub, display_name=name, email_verified=email_verified)
        db.session.add(user)
        db.session.commit()
    token = create_jwt(user.id)
    # Return JSON; frontend should store token securely
    return jsonify({"token": token, "user": {"id": user.id, "email": user.email, "display_name": user.display_name}})

# ---------- Route: Chat ----------
@app.route("/chat", methods=["POST"])
@auth_required
def chat():
    """
    Body:
    {
      "conversation_id": optional string,
      "message": "user message"
    }
    Returns assistant reply + updated summary + conversation id
    """
    data = request.json or {}
    message_text = (data.get("message") or "").strip()
    if not message_text:
        return jsonify({"error": "message required"}), 400

    # injection check
    if is_injection(message_text):
        return jsonify({"injection_detected": True}), 400

    conv_id = data.get("conversation_id")
    if conv_id:
        conv = Conversation.query.get(conv_id)
        if not conv or conv.user_id != g.current_user.id:
            return jsonify({"error": "conversation not found"}), 404
    else:
        conv = Conversation(user_id=g.current_user.id)
        db.session.add(conv)
        db.session.commit()

    # store user message
    m = Message(conversation_id=conv.id, sender="user", content=message_text)
    db.session.add(m)
    db.session.commit()

    # fetch last summary (if any) and last few messages
    summary_obj = Summary.query.filter_by(conversation_id=conv.id).first()
    previous_summary = summary_obj.summary_text if summary_obj else ""
    last_msgs = Message.query.filter_by(conversation_id=conv.id).order_by(Message.created_at.desc()).limit(6).all()
    last_msgs = list(reversed(last_msgs))  # chronological

    # build prompt/context for LLM
    prompt = f"Previous summary: {previous_summary}\n\nRecent messages:\n"
    for msg in last_msgs:
        prompt += f"{msg.sender}: {msg.content}\n"
    prompt += f"\nUser query: \"{message_text}\"\n\nRespond helpfully and produce a short summary."

    # call LLM (stub)
    llm_result = call_gemini(prompt)
    assistant_text = llm_result.get("response")
    summary_text = llm_result.get("summary")

    # store assistant message
    ma = Message(conversation_id=conv.id, sender="assistant", content=assistant_text, llm_meta=llm_result.get("meta"))
    db.session.add(ma)
    db.session.commit()

    # update or create summary (rolling)
    if summary_obj:
        summary_obj.summary_text = summary_text
        summary_obj.version = (summary_obj.version or 1) + 1
        summary_obj.last_updated_at = datetime.datetime.utcnow()
    else:
        summary_obj = Summary(conversation_id=conv.id, summary_text=summary_text)
        db.session.add(summary_obj)
    db.session.commit()

    return jsonify({
        "conversation_id": conv.id,
        "response": assistant_text,
        "summary": summary_text,
        "meta": llm_result.get("meta", {})
    })

# ---------- Route: Diagnosis ----------
@app.route("/diagnosis", methods=["POST"])
@auth_required
def diagnosis():
    """
    Body: {"symptoms": "free text describing symptoms"}
    Returns: predicted disorder, confidence, explanation (via LLM stub)
    """
    data = request.json or {}
    symptoms = (data.get("symptoms") or "").strip()
    if not symptoms:
        return jsonify({"error": "symptoms required"}), 400
    if is_injection(symptoms):
        return jsonify({"injection_detected": True}), 400

    prompt = f"User symptoms: {symptoms}\nAnswer with likely condition(s), short explanation, and confidence (0-1). Include recommended next step."
    llm_out = call_gemini(prompt)
    # store as a lightweight assessment record
    ass = Assessment(user_id=g.current_user.id, type="DIAGNOSIS_LLM", answers={"symptoms": symptoms}, score=0.0, confidence=llm_out.get("meta", {}).get("confidence", 0.0), interpretation=llm_out.get("response"))
    db.session.add(ass)
    db.session.commit()
    return jsonify({"assessment_id": ass.id, "interpretation": ass.interpretation, "confidence": ass.confidence, "raw": llm_out})

# ---------- Routes: Tests ----------
@app.route("/tests/<string:disorder>", methods=["GET"])
@auth_required
def get_test(disorder):
    # Return question set for requested disorder (MVP: ASRS6, PHQ2)
    disorder = disorder.upper()
    if disorder == "ADHD" or disorder == "ASRS6":
        q = {"type": "ADHD_ASRS6", "questions": [
            {"id":"q1","text":"How often do you have trouble wrapping up the final details of a project? (0-4)"},
            {"id":"q2","text":"How often do you have difficulty getting things in order when you have to do a task that requires organization? (0-4)"},
            {"id":"q3","text":"How often do you have problems remembering appointments or obligations? (0-4)"},
            {"id":"q4","text":"When you have a task that requires a lot of thought, how often do you avoid it? (0-4)"},
            {"id":"q5","text":"How often are you distracted by activity or noise around you? (0-4)"},
            {"id":"q6","text":"How often do you leave your seat in meetings or other situations where remaining seated is expected? (0-4)"}
        ]}
        return jsonify(q)
    elif disorder == "DEPRESSION" or disorder == "PHQ2":
        q = {"type":"PHQ2", "questions":[
            {"id":"q1","text":"Little interest or pleasure in doing things? (0-3)"},
            {"id":"q2","text":"Feeling down, depressed, or hopeless? (0-3)"}
        ]}
        return jsonify(q)
    else:
        return jsonify({"error":"unknown test type"}), 404

@app.route("/tests/submit", methods=["POST"])
@auth_required
def submit_test():
    """
    Body: {"type":"ADHD_ASRS6"|"PHQ2", "answers": { "q1": int, ... } }
    """
    data = request.json or {}
    t = data.get("type")
    answers = data.get("answers", {})
    if not t or t not in SCORE_FUNCS:
        return jsonify({"error": "unknown or missing test type"}), 400
    s, conf, interp = SCORE_FUNCS[t](answers)
    ass = Assessment(user_id=g.current_user.id, type=t, answers=answers, score=s, confidence=conf, interpretation=interp)
    db.session.add(ass)
    db.session.commit()
    return jsonify({"assessment_id": ass.id, "type": t, "score": s, "confidence": conf, "interpretation": interp}), 201

# ---------- Route: Learn ----------
@app.route("/learn/<string:topic>", methods=["GET"])
@auth_required
def learn(topic):
    # simple tag search
    tag = topic.lower()
    rows = LearnContent.query.filter(LearnContent.tags.contains([tag])).order_by(LearnContent.created_at.desc()).limit(20).all()
    # fallback: return all if none found
    if not rows:
        rows = LearnContent.query.order_by(LearnContent.created_at.desc()).limit(20).all()
    out = []
    for r in rows:
        out.append({"id": r.id, "title": r.title, "type": r.type, "url": r.url, "summary": r.summary, "tags": r.tags})
    return jsonify({"items": out})

# ---------- Route: Consultants (Google Places stub) ----------
@app.route("/consultants", methods=["GET"])
@auth_required
def consultants():
    """
    Query params: lat, lng, q (optional)
    MVP: if GOOGLE_PLACES_API_KEY set, call Google Places Nearby Search.
    Otherwise return a mocked response.
    """
    lat = request.args.get("lat")
    lng = request.args.get("lng")
    q = request.args.get("q", "psychiatrist")
    if not lat or not lng:
        return jsonify({"error": "lat and lng required"}), 400

    if GOOGLE_PLACES_API_KEY:
        # Replace/extend: implement server-side Google Places call, handle paging, JSON parse
        url = "https://maps.googleapis.com/maps/api/place/nearbysearch/json"
        params = {"location": f"{lat},{lng}", "keyword": q, "radius": 5000, "key": GOOGLE_PLACES_API_KEY}
        resp = requests.get(url, params=params, timeout=10)
        data = resp.json()
        results = []
        for r in data.get("results", [])[:10]:
            results.append({
                "name": r.get("name"),
                "vicinity": r.get("vicinity"),
                "place_id": r.get("place_id"),
                "types": r.get("types")
            })
        return jsonify({"results": results})
    else:
        # mocked
        mocked = [
            {"name": "Dr. A Sharma", "speciality": "Psychiatrist", "distance_m": 1200, "lat": float(lat) + 0.005, "lng": float(lng) - 0.003, "phone": "+91-99999", "place_id": "mock1"},
            {"name": "Ms. R. Patel", "speciality": "Clinical Psychologist", "distance_m": 3200, "lat": float(lat) - 0.004, "lng": float(lng) + 0.002, "phone": "+91-88888", "place_id": "mock2"}
        ]
        return jsonify({"results": mocked})
    
# ---------- Route: Contact ----------
@app.route("/contact", methods=["POST"])
@auth_required
def contact():
    data = request.json or {}
    message = data.get("message")
    name = data.get("name") or g.current_user.display_name
    email = data.get("email") or g.current_user.email
    if not message:
        return jsonify({"error": "message required"}), 400
    c = Contact(user_id=g.current_user.id, name=name, email=email, message=message)
    db.session.add(c)
    db.session.commit()
    # Optionally send email to admin here (not implemented)
    return jsonify({"status": "ok", "id": c.id}), 201

# ---------- Health ----------
@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "time": datetime.datetime.utcnow().isoformat()})


# ---------- Bootstrap ----------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        # add some sample learn content if empty
        if LearnContent.query.count() == 0:
            sample = LearnContent(
                title="Understanding ADHD - Short Overview",
                type="article",
                url="https://example.com/adhd-overview",
                summary="Short overview article about ADHD symptoms and non-medical coping strategies.",
                tags=["adhd","attention"]
            )
            db.session.add(sample)
            db.session.commit()
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)