from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from azure.cosmos import CosmosClient
import pandas as pd
import io
import os
from dotenv import load_dotenv
from datetime import datetime
import pytz
import json
import re

load_dotenv()

app = Flask(__name__)
CORS(app, supports_credentials=True)

# JWT configuration
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY", "super-secret-key")

# Initialize bcrypt and JWT
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# In-memory user store (for demo purposes)
users = {}
@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    if not username or not password:
        return jsonify({"msg": "Username and password required"}), 400
    if username in users:
        return jsonify({"msg": "Username already exists"}), 400
    pw_hash = bcrypt.generate_password_hash(password).decode("utf-8")
    users[username] = pw_hash
    return jsonify({"msg": "User registered successfully"}), 201


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    if not username or not password:
        return jsonify({"msg": "Username and password required"}), 400
    pw_hash = users.get(username)
    if not pw_hash or not bcrypt.check_password_hash(pw_hash, password):
        return jsonify({"msg": "Invalid username or password"}), 401
    access_token = create_access_token(identity=username)
    return jsonify(access_token=access_token, username=username), 200

# Cosmos DB connection (use env vars in production)
COSMOS_URI = os.getenv("COSMOS_URI", "https://ai-call-center-prod.documents.azure.com:443/")
COSMOS_KEY = os.getenv("COSMOS_KEY", "<your-primary-key>")
DATABASE_NAME = "ai-call-center-prod"
CALL_SUMMARY = "Call-Summary"
NURSE_HANDOFF = "Nurse_Handoff"

client = CosmosClient(COSMOS_URI, credential=COSMOS_KEY)
database = client.get_database_client(DATABASE_NAME)
call_summary_container = database.get_container_client(CALL_SUMMARY)
nurse_handoff_container = database.get_container_client(NURSE_HANDOFF)

def convert_to_timezone(dt_str, tz):
    if not dt_str:
        return None
    try:
        dt = datetime.fromisoformat(dt_str.replace("Z", "+00:00"))
        dt_utc = dt.astimezone(pytz.utc)
        dt_local = dt_utc.astimezone(tz)
        return dt_local.strftime("%m/%d/%Y %I:%M %p %Z")
    except Exception:
        return None

def extract_message_text(messages):
    if not messages:
        return ""
    role_map = {
        "assistant": "AI",
        "user": "Caller"
    }
    parts = []
    for m in messages:
        role = m.get("role", "").lower()
        role_label = role_map.get(role, "Unknown")
        content = m.get("content", "")
        parts.append(f"{role_label}: {content}")
    return " | ".join(parts)

def extract_patient_name(summary, messages):
    # Try to extract from summary
    if summary:
        patterns = [
            r"associated with ([A-Z][a-z]+(?: [A-Z][a-z]+){0,3})",
            r"(?:her|his|their) (?:mother|father|husband|wife|son|daughter), ([A-Z][a-z]+(?: [A-Z][a-z]+){0,3})",
            r"regarding patient ([A-Z][a-z]+(?: [A-Z][a-z]+){0,3})",
            r"patient ([A-Z][a-z]+(?: [A-Z][a-z]+){0,3})",
            r"decedent ([A-Z][a-z]+(?: [A-Z][a-z]+){0,3})"  # Added pattern to capture "decedent <Name>"
        ]
        for pattern in patterns:
            match = re.search(pattern, summary, re.IGNORECASE)
            if match:
                return match.group(1)

    # Try to extract from messages
    if messages:
        for m in messages:
            role = m.get("role", "").lower()
            content = m.get("content", "").lower()
            if role == "user":
                # Look for "patient name is"
                match = re.search(r"patient name is ([a-z]+(?: [a-z]+)*)", content)
                if match:
                    # Capitalize each word
                    name = " ".join(word.capitalize() for word in match.group(1).split())
                    return name
                # Look for "i'm with <name>"
                match = re.search(r"i['’]?m with ([a-z]+(?: [a-z]+)*)", content)
                if match:
                    name = " ".join(word.capitalize() for word in match.group(1).split())
                    return name
    return ""

@app.route("/audit-log", methods=["GET"])
@jwt_required()
def audit_log():
    start_date = request.args.get("start")
    end_date = request.args.get("end")
    if not start_date or not end_date:
        return jsonify({"msg": "start and end date parameters are required"}), 400
    user_tz_str = request.args.get("tz", "UTC")
    try:
        user_tz = pytz.timezone(user_tz_str)
    except Exception:
        user_tz = pytz.UTC

    # Normalize start_date and end_date to full-day ISO 8601 UTC timestamps
    try:
        start_dt = datetime.strptime(start_date, "%Y-%m-%d")
        start_iso = start_dt.strftime("%Y-%m-%dT00:00:00Z")
        end_dt = datetime.strptime(end_date, "%Y-%m-%d")
        end_iso = end_dt.strftime("%Y-%m-%dT23:59:59Z")
    except Exception:
        return jsonify({"msg": "Invalid date format, expected YYYY-MM-DD"}), 400

    query = f"""
    SELECT c.id, c.call_sid, c.patient_name, c.caller_name, c.caller_callback_number, c.is_agent_handoff,
           c.summary, c.call_duration, c.call_length, c.category, c.created_at, c.updated_at,
           c.status, c.message_otp, c.nurse_call_number, c.messages, c.call_from, c.recording_filename
    FROM c
    WHERE c.created_at >= '{start_iso}' AND c.created_at <= '{end_iso}'
    """
    call_summary = list(call_summary_container.query_items(
        query=query,
        enable_cross_partition_query=True
    ))

    nurse_handoff = list(nurse_handoff_container.read_all_items())

    # Join on call_sid
    handoff_dict = {nh["call_sid"]: nh for nh in nurse_handoff}
    combined = []
    for cs in call_summary:
        nh = handoff_dict.get(cs["call_sid"], {})
        combined.append({
            "id": cs.get("id"),
            "call_sid": cs.get("call_sid"),
            "patient_name": extract_patient_name(cs.get("summary"), cs.get("messages", [])),
            "patient_name_encoded": cs.get("patient_name"),
            "caller_name": cs.get("caller_name"),
            "caller_callback_number": cs.get("caller_callback_number"),
            "is_agent_handoff": cs.get("is_agent_handoff"),
            "summary": cs.get("summary"),
            "call_duration": cs.get("call_duration"),
            "call_length": cs.get("call_length"),
            "category": cs.get("category"),
            "created_at_summary": convert_to_timezone(cs.get("created_at"), user_tz),
            "updated_at_summary": convert_to_timezone(cs.get("updated_at"), user_tz),
            "status_summary": cs.get("status"),
            "message_otp": cs.get("message_otp"),
            "nurse_call_number": cs.get("nurse_call_number"),
            "messages": extract_message_text(cs.get("messages", [])),
            "call_from": cs.get("call_from"),
            "recording_filename": cs.get("recording_filename"),
            "nurse_id": nh.get("nurse_id"),
            "nurse_name": nh.get("nurse_name"),
            "nurse_phone": nh.get("phone"),
            "reason_for_escalation": nh.get("reason_for_escalation"),
            "created_at_handoff": convert_to_timezone(nh.get("created_at"), user_tz),
            "updated_at_handoff": convert_to_timezone(nh.get("updated_at"), user_tz),
            "status_handoff": nh.get("status")
        })

    return jsonify(combined)

@app.route("/audit-log/export", methods=["GET"])
@jwt_required()
def export_audit_log():
    start_date = request.args.get("start")
    end_date = request.args.get("end")
    if not start_date or not end_date:
        return jsonify({"msg": "start and end date parameters are required"}), 400
    user_tz_str = request.args.get("tz", "UTC")
    try:
        user_tz = pytz.timezone(user_tz_str)
    except Exception:
        user_tz = pytz.UTC

    # Normalize start_date and end_date to full-day ISO 8601 UTC timestamps
    try:
        start_dt = datetime.strptime(start_date, "%Y-%m-%d")
        start_iso = start_dt.strftime("%Y-%m-%dT00:00:00Z")
        end_dt = datetime.strptime(end_date, "%Y-%m-%d")
        end_iso = end_dt.strftime("%Y-%m-%dT23:59:59Z")
    except Exception:
        return jsonify({"msg": "Invalid date format, expected YYYY-MM-DD"}), 400

    query = f"""
    SELECT c.id, c.call_sid, c.patient_name, c.caller_name, c.caller_callback_number, c.is_agent_handoff,
           c.summary, c.call_duration, c.call_length, c.category, c.created_at, c.updated_at,
           c.status, c.message_otp, c.nurse_call_number, c.messages, c.call_from, c.recording_filename
    FROM c
    WHERE c.created_at >= '{start_iso}' AND c.created_at <= '{end_iso}'
    """
    call_summary = list(call_summary_container.query_items(
        query=query,
        enable_cross_partition_query=True
    ))

    nurse_handoff = list(nurse_handoff_container.read_all_items())

    # Join on call_sid
    handoff_dict = {nh["call_sid"]: nh for nh in nurse_handoff}
    combined = []
    for cs in call_summary:
        nh = handoff_dict.get(cs["call_sid"], {})
        combined.append({
            "id": cs.get("id"),
            "call_sid": cs.get("call_sid"),
            "patient_name": extract_patient_name(cs.get("summary"), cs.get("messages", [])),
            "patient_name_encoded": cs.get("patient_name"),
            "caller_name": cs.get("caller_name"),
            "caller_callback_number": cs.get("caller_callback_number"),
            "is_agent_handoff": cs.get("is_agent_handoff"),
            "summary": cs.get("summary"),
            "call_duration": cs.get("call_duration"),
            "call_length": cs.get("call_length"),
            "category": cs.get("category"),
            "created_at_summary": convert_to_timezone(cs.get("created_at"), user_tz),
            "updated_at_summary": convert_to_timezone(cs.get("updated_at"), user_tz),
            "status_summary": cs.get("status"),
            "message_otp": cs.get("message_otp"),
            "nurse_call_number": cs.get("nurse_call_number"),
            "messages": extract_message_text(cs.get("messages", [])),
            "call_from": cs.get("call_from"),
            "recording_filename": cs.get("recording_filename"),
            "nurse_id": nh.get("nurse_id"),
            "nurse_name": nh.get("nurse_name"),
            "nurse_phone": nh.get("phone"),
            "reason_for_escalation": nh.get("reason_for_escalation"),
            "created_at_handoff": convert_to_timezone(nh.get("created_at"), user_tz),
            "updated_at_handoff": convert_to_timezone(nh.get("updated_at"), user_tz),
            "status_handoff": nh.get("status")
        })

    df = pd.DataFrame(combined)

    output = io.BytesIO()
    df.to_csv(output, index=False)
    output.seek(0)
    return send_file(output, mimetype="text/csv", as_attachment=True, download_name="audit_log.csv")

@app.route("/")
def index():
    return "✅ AI Call Center Audit Log API is running"

if __name__ == "__main__":
    app.run(debug=True, port=5001)