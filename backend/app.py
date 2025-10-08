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
    if not summary and not messages:
        return ""

    text_sources = [summary] if summary else []
    if messages:
        for m in messages:
            if m.get("role") == "user":
                text_sources.append(m.get("content", ""))

    text = " ".join(text_sources)
    text = re.sub(r"’s\b|\'s\b", "", text)  # remove possessive
    text = re.sub(r"[^A-Za-z0-9\s,.]", " ", text)  # remove noise

    # Common relationship and context cues
    relationship_terms = [
        "father", "mother", "dad", "mom", "husband", "wife", "son", "daughter",
        "grandmother", "grandfather", "brother", "sister", "cousin", "uncle", "aunt"
    ]

    skip_words = {"pain", "pills", "medication", "refill", "results", "test", "issue", "concern"}

    patterns = [
        # Handles cases like "for her mother-in-law, Roma Theriot" or "for her mother in law Roma Theriot"
        r"(?:for|about|regarding|called about|called regarding)\s+(?:her|his|their)?\s*(?:mother|father)(?:[-\s]?in[-\s]?law)?[, ]+\s*([A-Z][a-z]+(?: [A-Z][a-z]+){0,3})",

        r"(?:regarding|in regards to)\s+([A-Z][a-z]+(?: [A-Z][a-z]+){0,3})",
        # 1. Relationship pattern with trailing comma and "passed away" context
        r"(?:about|regarding|for|called about|called regarding|her|his|their)\s+(?:his|her|their)?\s*(?:"
        + "|".join(relationship_terms) +
        r"),?\s+([A-Z][a-z]+(?: [A-Z][a-z]+){0,3})(?:, passed away)?",

        # 2. Relationship pattern with 'about' and trailing comma
        r"about\s+(?:my|his|her|their)?\s*(?:"
        + "|".join(relationship_terms) +
        r"),?\s*([A-Z][a-z]+(?: [A-Z][a-z]+){0,3})",

        # 3. Title + name pattern ("Miss Mavis Hilburn")
        r"(?:Miss|Mrs|Ms|Mr)\.?\s+([A-Z][a-z]+(?: [A-Z][a-z]+){0,2})",

        # 4. Simple 'patient' + proper name (not lowercase words)
        r"patient\s+([A-Z][a-z]+(?: [A-Z][a-z]+){0,3})",

        # 5. 'associated with <Name>'
        r"associated with ([A-Z][a-z]+(?: [A-Z][a-z]+){0,3})",

        # 6. 'decedent <Name>'
        r"decedent\s+([A-Z][a-z]+(?: [A-Z][a-z]+){0,3})",

        # 7. 'refill on Miss <Name>' or similar with possessive or trailing words
        r"refill on (?:Miss|Mrs|Mr|Ms)?\.?\s*([A-Z][a-z]+(?: [A-Z][a-z]+){0,3})(?:’s|\'s)?(?: medication)?",

        # 7.5 Handles "reported that resident Gerald Gutros" or similar
        r"reported that (?:the )?(?:resident|patient)\s+([A-Z][a-z]+(?: [A-Z][a-z]+){0,3})",

        # 8. Handles "requested ... for [Name]" (covers cases like Cheryl requesting for Sylvia Blackwell)
        r"requested (?:an on-call nurse|medication|a refill|assistance)? for\s+([A-Z][a-z]+(?: [A-Z][a-z]+){0,3})(?=[\s,.]|$)",

        # 9. Handles "mother-in-law, [Name]" or "father-in-law, [Name]" (handles cases like Mary Theriot requesting for Roma Theriot)
        r"(?:mother|father|in-law|mother-in-law|father-in-law),\s+([A-Z][a-z]+(?: [A-Z][a-z]+){0,3})",

        # 10. Handles "regarding patient [Name]" or "regarding [Name]" (covers Dawn Gulledge, Regina Calhoun, and similar)
        r"(?:regarding|in regards to)\s+(?:patient\s+)?([A-Z][a-z]+(?: [A-Z][a-z]+){0,3})(?=[\s,.]|$)",

        # 11. Handles "for [Name]" at sentence end when request verbs omitted (backup match for simple phrasing)
        r"\bfor\s+([A-Z][a-z]+(?: [A-Z][a-z]+){0,3})(?=[\s,.]|$)",

        # 12. Handles conversation cases where AI asks for the patient name and Caller provides it
        r"(?:patient'?s full name[, ]?(?:please)?|patient name is)\s*[:\-]?\s*([A-Z][a-z]+(?: [A-Z][a-z]+){0,3})",
    ]

    for idx, pattern in enumerate(patterns, 1):
        match = re.search(pattern, text)
        if match:
            name = match.group(1).strip(".,; ")
            # Filter out lowercase words pretending to be names
            if name.lower() in skip_words:
                continue
            # Exclude single words that are not likely proper nouns
            if len(name.split()) == 1 and name[0].islower():
                continue
            return name

    # Fallback: Check conversation messages if no name found in summary
    if not summary and messages:
        for msg in messages:
            content = msg.get("content", "")
            if re.search(r"(patient|name|full name)", content, re.IGNORECASE):
                name_match = re.search(r"\b([A-Z][a-z]+(?: [A-Z][a-z]+){0,3})\b", content)
                if name_match:
                    name = name_match.group(1).strip(".,; ")
                    if name.lower() not in skip_words:
                        return name

    # Secondary fallback: handle cases where caller spells name letter-by-letter
    if not summary and messages:
        for msg in messages:
            content = msg.get("content", "")
            # Detect spelled names (e.g., "k e n d r a h a r v e y")
            spelled_match = re.search(r"Caller:\s*([a-z](?:\s+[a-z]){2,})", content)
            if spelled_match:
                spelled_text = spelled_match.group(1)
                # Collapse spaces and reconstruct name
                cleaned = "".join(spelled_text.split())
                # Capitalize if it looks like a real name
                if cleaned.isalpha() and len(cleaned) > 3:
                    name_guess = cleaned.capitalize()
                    return name_guess

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