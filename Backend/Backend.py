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
