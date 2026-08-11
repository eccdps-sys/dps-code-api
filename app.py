from flask import Flask, jsonify, redirect, request, session
import random
import string
import os
import json
import secrets
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen
from postgrest.exceptions import APIError
from supabase import create_client, Client

app = Flask(__name__)

# Browser sessions are used only by the DPS dashboard. BotGhost continues to
# authenticate with API_KEY, so it does not need a browser session.
app.config.update(
    SECRET_KEY=os.environ.get("OAUTH_SESSION_SECRET"),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "true").lower() == "true",
    SESSION_COOKIE_SAMESITE="Lax",
)

# =====================
# SECURITY
# (unchanged from the original app.py)
# =====================

API_KEY = os.environ.get("API_KEY")

DISCORD_CLIENT_ID = os.environ.get("DISCORD_CLIENT_ID")
DISCORD_CLIENT_SECRET = os.environ.get("DISCORD_CLIENT_SECRET")
DISCORD_REDIRECT_URI = os.environ.get("DISCORD_REDIRECT_URI")
DASHBOARD_ORIGIN = os.environ.get("DASHBOARD_ORIGIN", "").rstrip("/")

# Change these values to adjust dashboard access later. Every protected API
# route checks this map, so hiding a button in the UI is never the only guard.
CLEARANCE_POLICY = {
    "view_dashboard": 1,
    "view_agents": 1,
    "view_analytics": 2,
    "add_case_note": 1,
    "add_evidence": 1,
    "manage_dockets": 2,
    "reassign_docket": 3,
    "decide_appeal": 4,
    "manage_agents": 5,
    "delete_docket": 5,
}


def verify_api_key():
    auth = request.headers.get("Authorization")
    return bool(API_KEY) and bool(auth) and secrets.compare_digest(auth, API_KEY)


def oauth_configured():
    return all([
        app.config.get("SECRET_KEY"),
        DISCORD_CLIENT_ID,
        DISCORD_CLIENT_SECRET,
        DISCORD_REDIRECT_URI,
        DASHBOARD_ORIGIN,
    ])


def active_agent_from_session():
    """Return the live agent row for this browser session, if eligible."""
    discord_id = session.get("discord_id")
    if not discord_id:
        return None

    row = db_get_agent_row(str(discord_id))
    if not row or str(row.get("status") or "").strip().lower() != "active":
        session.clear()
        return None
    return row


def has_permission(agent_row, permission):
    try:
        level = int(agent_row.get("clearance_level"))
    except (TypeError, ValueError):
        return False
    return level >= CLEARANCE_POLICY[permission]


def authorize_dashboard(permission):
    """Permit BotGhost's API key or an active, cleared browser session."""
    if verify_api_key():
        return None

    agent_row = active_agent_from_session()
    if not agent_row:
        return error_response("Sign-in required", 401)
    if not has_permission(agent_row, permission):
        return error_response("Insufficient clearance", 403)
    return None


@app.after_request
def apply_dashboard_cors(response):
    """Allow credentialed requests only from the configured dashboard URL."""
    origin = request.headers.get("Origin")
    if origin and origin == DASHBOARD_ORIGIN:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, PATCH, DELETE, OPTIONS"
        response.headers.add("Vary", "Origin")
    return response


# =====================
# GENERATORS
# (unchanged from the original app.py)
# =====================

def numbers(amount):
    return ''.join(random.choice(string.digits) for _ in range(amount))


def letters(amount):
    return ''.join(random.choice(string.ascii_uppercase) for _ in range(amount))


# =====================================================================
# SUPABASE CLIENT
# =====================================================================
# Replaces: reports.json, DATA_DIR, LOCK_FILE, file locking, _load_reports(),
# _save_reports(). All persistence now goes through Supabase Postgres.
#
# SUPABASE_URL and SUPABASE_KEY are required env vars. SUPABASE_KEY should
# be the *service_role* key (Project Settings -> API -> service_role),
# never the anon/public key, since this server writes on behalf of every
# BotGhost user and must bypass Row Level Security.

SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")

if not SUPABASE_URL or not SUPABASE_KEY:
    raise RuntimeError(
        "SUPABASE_URL and SUPABASE_KEY environment variables are required."
    )

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

REPORTS_TABLE = "reports"
NOTES_TABLE = "notes"
EVIDENCE_TABLE = "evidence"
TIMELINE_TABLE = "timeline"
AGENTS_TABLE = "agents"

REQUIRED_CREATE_FIELDS = ["report_id", "reporter", "reported", "reason"]

# Fields that BotGhost/clients are allowed to directly overwrite via PATCH.
# notes/evidence/timeline stay append-only via their dedicated endpoints,
# so a PATCH can't accidentally wipe history.
PATCHABLE_FIELDS = {
    "reporter",
    "reported",
    "notes",
    "reason",
    "status",
    "assigned_agent",
    "is_supervisor"
}


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def error_response(message, status_code):
    return jsonify({"success": False, "error": message}), status_code


class ReportNotFound(Exception):
    pass


class AgentNotFound(Exception):
    pass


# =====================================================================
# DATA ACCESS HELPERS
# All Supabase calls are centralized here so the route handlers below
# stay identical in shape to the original JSON-file version.
# =====================================================================

def db_get_report_row(report_id):
    """Fetch the raw reports row, or None if it doesn't exist."""
    resp = (
        supabase.table(REPORTS_TABLE)
        .select("*")
        .eq("report_id", report_id)
        .limit(1)
        .execute()
    )
    rows = resp.data or []
    return rows[0] if rows else None


def db_get_notes(report_id):
    resp = (
        supabase.table(NOTES_TABLE)
        .select("*")
        .eq("report_id", report_id)
        .order("created_at", desc=False)
        .execute()
    )
    return resp.data or []


def db_get_evidence(report_id):
    resp = (
        supabase.table(EVIDENCE_TABLE)
        .select("*")
        .eq("report_id", report_id)
        .order("created_at", desc=False)
        .execute()
    )
    return resp.data or []


def db_get_timeline(report_id):
    resp = (
        supabase.table(TIMELINE_TABLE)
        .select("*")
        .eq("report_id", report_id)
        .order("created_at", desc=False)
        .execute()
    )
    return resp.data or []


def db_get_agent_row(discord_id):
    """Fetch the raw agents row by discord_id (the primary key), or None."""
    resp = (
        supabase.table(AGENTS_TABLE)
        .select("*")
        .eq("discord_id", discord_id)
        .limit(1)
        .execute()
    )
    rows = resp.data or []
    return rows[0] if rows else None


def serialize_note(row):
    return {
        "note": row.get("note"),
        "author": row.get("author"),
        "timestamp": row.get("created_at"),
    }


def serialize_evidence(row):
    return {
        "description": row.get("description"),
        "url": row.get("url"),
        "submitted_by": row.get("submitted_by"),
        "timestamp": row.get("created_at"),
    }


def serialize_timeline(row):
    return {
        "event": row.get("event"),
        "by": row.get("by"),
        "timestamp": row.get("created_at"),
    }


def serialize_agent(row):
    """Public shape for an agents row. Nullable fields stay null/absent
    until the agent has actually reached that onboarding phase."""
    return {
        "discord_id": row.get("discord_id"),
        "name": row.get("name"),
        "status": row.get("status"),
        "security_id": row.get("security_id"),
        "agreement_id": row.get("agreement_id"),
        "agent_id": row.get("agent_id"),
        "clearance_level": row.get("clearance_level"),
        "clearance_id": row.get("clearance_id"),
        "created_at": row.get("created_at"),
        "updated_at": row.get("updated_at"),
    }


def build_report_json(report_row, notes_rows=None, evidence_rows=None, timeline_rows=None):
    """
    Assembles the full report object in exactly the shape BotGhost/the old
    reports.json version returned: base fields plus notes/evidence/timeline
    arrays.
    """
    if notes_rows is None:
        notes_rows = db_get_notes(report_row["report_id"])
    if evidence_rows is None:
        evidence_rows = db_get_evidence(report_row["report_id"])
    if timeline_rows is None:
        timeline_rows = db_get_timeline(report_row["report_id"])

    return {
        "report_id": report_row["report_id"],
        "reporter": report_row.get("reporter"),
        "reported": report_row.get("reported"),
        "reason": report_row.get("reason"),
        "status": report_row.get("status"),
        "assigned_agent": report_row.get("assigned_agent"),
        "notes": [serialize_note(r) for r in notes_rows],
        "evidence": [serialize_evidence(r) for r in evidence_rows],
        "timeline": [serialize_timeline(r) for r in timeline_rows],
        "created_at": report_row.get("created_at"),
        "updated_at": report_row.get("updated_at"),
        "is_supervisor": report_row.get("is_supervisor"),
    }


def fetch_full_report_or_raise(report_id):
    row = db_get_report_row(report_id)
    if row is None:
        raise ReportNotFound(report_id)
    return build_report_json(row)


def fetch_agent_or_raise(discord_id):
    row = db_get_agent_row(discord_id)
    if row is None:
        raise AgentNotFound(discord_id)
    return serialize_agent(row)


def _summarize_notes_column(notes_rows):
    """Builds the flat, human-readable reports.notes TEXT column."""
    return " | ".join(
        f"[{r.get('author', 'Unknown')}] {r.get('note', '')}" for r in notes_rows
    )


def _summarize_evidence_column(evidence_rows):
    """Builds the flat, human-readable reports.evidence TEXT column."""
    return " | ".join(
        f"[{r.get('submitted_by', 'Unknown')}] {r.get('description', '')}"
        for r in evidence_rows
    )


# =====================
# HOME
# =====================

@app.route("/")
def home():
    return "DPS API Online"


# =====================
# DASHBOARD AUTHENTICATION
# =====================

def dashboard_redirect(path, **params):
    query = urlencode(params)
    suffix = f"?{query}" if query else ""
    return redirect(f"{DASHBOARD_ORIGIN}{path}{suffix}")


def discord_json_request(url, method="GET", data=None):
    headers = {"Accept": "application/json"}
    if data is not None:
        data = urlencode(data).encode("utf-8")
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    req = Request(url, data=data, headers=headers, method=method)
    with urlopen(req, timeout=10) as response:
        return json.loads(response.read().decode("utf-8"))


@app.route("/auth/discord/login", methods=["GET"])
def discord_login():
    if not oauth_configured():
        return error_response("Discord OAuth is not configured", 503)

    state = secrets.token_urlsafe(32)
    session.clear()
    session["oauth_state"] = state
    params = {
        "client_id": DISCORD_CLIENT_ID,
        "redirect_uri": DISCORD_REDIRECT_URI,
        "response_type": "code",
        "scope": "identify",
        "state": state,
    }
    return redirect("https://discord.com/oauth2/authorize?" + urlencode(params))


@app.route("/auth/discord/callback", methods=["GET"])
def discord_callback():
    if not oauth_configured():
        return error_response("Discord OAuth is not configured", 503)

    if request.args.get("error"):
        return dashboard_redirect("/login", error="discord_authorization_denied")

    state = request.args.get("state")
    expected_state = session.pop("oauth_state", None)
    code = request.args.get("code")
    if not code or not state or not expected_state or not secrets.compare_digest(state, expected_state):
        return dashboard_redirect("/login", error="invalid_oauth_state")

    try:
        token = discord_json_request(
            "https://discord.com/api/oauth2/token",
            method="POST",
            data={
                "client_id": DISCORD_CLIENT_ID,
                "client_secret": DISCORD_CLIENT_SECRET,
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": DISCORD_REDIRECT_URI,
            },
        )
        access_token = token.get("access_token")
        if not access_token:
            raise ValueError("Discord did not return an access token")
    except (HTTPError, URLError, ValueError, json.JSONDecodeError):
        return dashboard_redirect("/login", error="discord_verification_failed")

    # /users/@me requires the access token; use a separate authenticated call.
    try:
        req = Request(
            "https://discord.com/api/users/@me",
            headers={"Accept": "application/json", "Authorization": f"Bearer {access_token}"},
        )
        with urlopen(req, timeout=10) as response:
            user = json.loads(response.read().decode("utf-8"))
    except (HTTPError, URLError, json.JSONDecodeError):
        return dashboard_redirect("/login", error="discord_verification_failed")

    discord_id = str(user.get("id", "")).strip()
    agent = db_get_agent_row(discord_id) if discord_id else None
    if not agent:
        return dashboard_redirect("/login", error="not_a_dps_agent")
    if str(agent.get("status") or "").strip().lower() != "active":
        return dashboard_redirect("/login", error="agent_not_active")

    session.clear()
    session["discord_id"] = discord_id
    return dashboard_redirect("/dashboard")


@app.route("/auth/me", methods=["GET"])
def auth_me():
    agent = active_agent_from_session()
    if not agent:
        return error_response("Sign-in required", 401)

    return jsonify({
        "success": True,
        "agent": serialize_agent(agent),
        "permissions": {
            permission: has_permission(agent, permission)
            for permission in CLEARANCE_POLICY
        },
        "minimum_clearances": CLEARANCE_POLICY,
    }), 200


@app.route("/auth/logout", methods=["POST"])
def auth_logout():
    session.clear()
    return jsonify({"success": True}), 200


# =====================
# AGREEMENT CODE
# =====================

@app.route("/generate/agreement")
def agreement():
    if not verify_api_key():
        return jsonify({"error": "Unauthorized"}), 401
    code = f"AGM-{numbers(5)}"
    return jsonify({"code": code})


# =====================
# AGENT ID
# =====================

@app.route("/generate/agent")
def agent():
    if not verify_api_key():
        return jsonify({"error": "Unauthorized"}), 401
    code = f"DPS-AG-{numbers(5)}"
    return jsonify({"code": code})


# =====================
# JOIN CODE
# =====================

@app.route("/generate/join")
def join():
    if not verify_api_key():
        return jsonify({"error": "Unauthorized"}), 401
    code = f"SC-{numbers(3)}{letters(1)}{numbers(1)}"
    return jsonify({"code": code})


# =====================
# CASE NUMBER
# =====================

@app.route("/generate/case")
def case():
    if not verify_api_key():
        return jsonify({"error": "Unauthorized"}), 401
    code = f"DPS-CASE-{numbers(5)}"
    return jsonify({"code": code})


# =====================
# INVESTIGATION ID
# =====================

@app.route("/generate/investigation")
def investigation():
    if not verify_api_key():
        return jsonify({"error": "Unauthorized"}), 401
    code = f"INV-{numbers(5)}"
    return jsonify({"code": code})


# =====================
# CLEARANCE ID
# =====================

@app.route("/generate/clearance")
def clearance():
    if not verify_api_key():
        return jsonify({"error": "Unauthorized"}), 401
    code = f"CL-{numbers(3)}"
    return jsonify({"code": code})


# =====================================================================
# REPORT / CASE MANAGEMENT
# =====================================================================

@app.route("/reports/create", methods=["POST"])
def create_report():
    denied = authorize_dashboard("manage_dockets")
    if denied:
        return denied

    payload = request.get_json(silent=True)
    if payload is None:
        return error_response("Request body must be valid JSON", 400)

    missing = [f for f in REQUIRED_CREATE_FIELDS if not str(payload.get(f, "")).strip()]
    if missing:
        return error_response(f"Missing required field(s): {', '.join(missing)}", 400)

    report_id = str(payload["report_id"]).strip()
    status = payload.get("status", "Open")
    assigned_agent = payload.get("assigned_agent", "Unassigned")

    try:
        existing = db_get_report_row(report_id)
        if existing is not None:
            return error_response(f"Report '{report_id}' already exists", 409)

        now = _now_iso()
        insert_row = {
            "report_id": report_id,
            "reporter": payload["reporter"],
            "reported": payload["reported"],
            "reason": payload["reason"],
            "notes": "",
            "evidence": "",
            "status": status,
            "assigned_agent": assigned_agent,
            "created_at": now,
            "updated_at": now,
            "is_supervisor": payload.get("is_supervisor", False)
        }

        supabase.table(REPORTS_TABLE).insert(insert_row).execute()

        # Seed timeline with a "Report created" entry, matching prior behavior.
        supabase.table(TIMELINE_TABLE).insert({
            "report_id": report_id,
            "event": "Report created",
            "by": payload.get("reporter", "Unknown"),
            "created_at": now,
        }).execute()

        report = fetch_full_report_or_raise(report_id)

    except APIError as e:
        return error_response(f"Database error: {e.message if hasattr(e, 'message') else str(e)}", 500)
    except Exception as e:
        return error_response(f"Unexpected server error: {str(e)}", 500)

    return jsonify({"success": True, "report": report}), 201


@app.route("/reports/<report_id>", methods=["GET"])
def get_report(report_id):
    denied = authorize_dashboard("view_dashboard")
    if denied:
        return denied

    try:
        row = db_get_report_row(report_id)
        if row is None:
            return error_response(f"Report '{report_id}' not found", 404)
        report = build_report_json(row)
    except APIError as e:
        return error_response(f"Database error: {e.message if hasattr(e, 'message') else str(e)}", 500)
    except Exception as e:
        return error_response(f"Unexpected server error: {str(e)}", 500)

    return jsonify({"success": True, "report": report}), 200


@app.route("/reports", methods=["GET"])
def list_reports():
    """
    Optional convenience endpoint: list all reports, with optional
    ?status=Open filtering. Handy for BotGhost embeds that show open cases.
    """
    denied = authorize_dashboard("view_dashboard")
    if denied:
        return denied

    status_filter = request.args.get("status")

    try:
        query = supabase.table(REPORTS_TABLE).select("*").order("created_at", desc=True)
        if status_filter:
            query = query.ilike("status", status_filter)
        resp = query.execute()
        rows = resp.data or []
        reports = [build_report_json(row) for row in rows]
    except APIError as e:
        return error_response(f"Database error: {e.message if hasattr(e, 'message') else str(e)}", 500)
    except Exception as e:
        return error_response(f"Unexpected server error: {str(e)}", 500)

    return jsonify({"success": True, "count": len(reports), "reports": reports}), 200


@app.route("/reports/<report_id>/update", methods=["PATCH"])
def update_report(report_id):
    denied = authorize_dashboard("manage_dockets")
    if denied:
        return denied

    payload = request.get_json(silent=True)
    if payload is None:
        return error_response("Request body must be valid JSON", 400)

    disallowed = [k for k in payload.keys() if k not in PATCHABLE_FIELDS]
    if disallowed:
        return error_response(
            f"Field(s) not updatable via /update: {', '.join(disallowed)}. "
            f"Use the dedicated notes/evidence/timeline endpoints for those.",
            400,
        )

    if not payload:
        return error_response("No updatable fields provided", 400)

    try:
        existing = db_get_report_row(report_id)
        if existing is None:
            return error_response(f"Report '{report_id}' not found", 404)

        changed_fields = [
            field for field, value in payload.items() if existing.get(field) != value
        ]

        if changed_fields:
            now = _now_iso()
            update_data = {field: payload[field] for field in changed_fields}
            update_data["updated_at"] = now

            supabase.table(REPORTS_TABLE).update(update_data).eq(
                "report_id", report_id
            ).execute()

            supabase.table(TIMELINE_TABLE).insert({
                "report_id": report_id,
                "event": f"Updated field(s): {', '.join(changed_fields)}",
                "by": payload.get("assigned_agent") or "System",
                "created_at": now,
            }).execute()

        report = fetch_full_report_or_raise(report_id)

    except ReportNotFound:
        return error_response(f"Report '{report_id}' not found", 404)
    except APIError as e:
        return error_response(f"Database error: {e.message if hasattr(e, 'message') else str(e)}", 500)
    except Exception as e:
        return error_response(f"Unexpected server error: {str(e)}", 500)

    return jsonify({"success": True, "report": report}), 200


@app.route("/reports/<report_id>/notes", methods=["POST"])
def add_note(report_id):
    denied = authorize_dashboard("add_case_note")
    if denied:
        return denied

    payload = request.get_json(silent=True)
    if payload is None:
        return error_response("Request body must be valid JSON", 400)

    note_text = str(payload.get("note", "")).strip()
    if not note_text:
        return error_response("Field 'note' is required", 400)

    author = str(payload.get("author", "Unknown")).strip() or "Unknown"

    try:
        existing = db_get_report_row(report_id)
        if existing is None:
            return error_response(f"Report '{report_id}' not found", 404)

        now = _now_iso()

        supabase.table(NOTES_TABLE).insert({
            "report_id": report_id,
            "note": note_text,
            "author": author,
            "created_at": now,
        }).execute()

        supabase.table(TIMELINE_TABLE).insert({
            "report_id": report_id,
            "event": f"Note added by {author}",
            "by": author,
            "created_at": now,
        }).execute()

        notes_rows = db_get_notes(report_id)
        supabase.table(REPORTS_TABLE).update({
            "notes": _summarize_notes_column(notes_rows),
            "updated_at": now,
        }).eq("report_id", report_id).execute()

        entry = {"note": note_text, "author": author, "timestamp": now}
        report = fetch_full_report_or_raise(report_id)

    except ReportNotFound:
        return error_response(f"Report '{report_id}' not found", 404)
    except APIError as e:
        return error_response(f"Database error: {e.message if hasattr(e, 'message') else str(e)}", 500)
    except Exception as e:
        return error_response(f"Unexpected server error: {str(e)}", 500)

    return jsonify({"success": True, "note": entry, "report": report}), 201


@app.route("/reports/<report_id>/evidence", methods=["POST"])
def add_evidence(report_id):
    denied = authorize_dashboard("add_evidence")
    if denied:
        return denied

    payload = request.get_json(silent=True)
    if payload is None:
        return error_response("Request body must be valid JSON", 400)

    description = str(payload.get("description", "")).strip()
    if not description:
        return error_response("Field 'description' is required", 400)

    submitted_by = str(payload.get("submitted_by", "Unknown")).strip() or "Unknown"
    url = payload.get("url", "")

    try:
        existing = db_get_report_row(report_id)
        if existing is None:
            return error_response(f"Report '{report_id}' not found", 404)

        now = _now_iso()

        supabase.table(EVIDENCE_TABLE).insert({
            "report_id": report_id,
            "description": description,
            "url": url,
            "submitted_by": submitted_by,
            "created_at": now,
        }).execute()

        supabase.table(TIMELINE_TABLE).insert({
            "report_id": report_id,
            "event": f"Evidence added by {submitted_by}",
            "by": submitted_by,
            "created_at": now,
        }).execute()

        evidence_rows = db_get_evidence(report_id)
        supabase.table(REPORTS_TABLE).update({
            "evidence": _summarize_evidence_column(evidence_rows),
            "updated_at": now,
        }).eq("report_id", report_id).execute()

        entry = {
            "description": description,
            "url": url,
            "submitted_by": submitted_by,
            "timestamp": now,
        }
        report = fetch_full_report_or_raise(report_id)

    except ReportNotFound:
        return error_response(f"Report '{report_id}' not found", 404)
    except APIError as e:
        return error_response(f"Database error: {e.message if hasattr(e, 'message') else str(e)}", 500)
    except Exception as e:
        return error_response(f"Unexpected server error: {str(e)}", 500)

    return jsonify({"success": True, "evidence": entry, "report": report}), 201


@app.route("/reports/<report_id>/timeline", methods=["POST"])
def add_timeline_event(report_id):
    denied = authorize_dashboard("manage_dockets")
    if denied:
        return denied

    payload = request.get_json(silent=True)
    if payload is None:
        return error_response("Request body must be valid JSON", 400)

    event_text = str(payload.get("event", "")).strip()
    if not event_text:
        return error_response("Field 'event' is required", 400)

    by = str(payload.get("by", "System")).strip() or "System"

    try:
        existing = db_get_report_row(report_id)
        if existing is None:
            return error_response(f"Report '{report_id}' not found", 404)

        now = _now_iso()

        supabase.table(TIMELINE_TABLE).insert({
            "report_id": report_id,
            "event": event_text,
            "by": by,
            "created_at": now,
        }).execute()

        supabase.table(REPORTS_TABLE).update({
            "updated_at": now,
        }).eq("report_id", report_id).execute()

        entry = {"event": event_text, "by": by, "timestamp": now}
        report = fetch_full_report_or_raise(report_id)

    except ReportNotFound:
        return error_response(f"Report '{report_id}' not found", 404)
    except APIError as e:
        return error_response(f"Database error: {e.message if hasattr(e, 'message') else str(e)}", 500)
    except Exception as e:
        return error_response(f"Unexpected server error: {str(e)}", 500)

    return jsonify({"success": True, "event": entry, "report": report}), 201


@app.route("/reports/<report_id>", methods=["DELETE"])
def delete_report(report_id):
    """
    Hard-delete a report. Child rows in notes/evidence/timeline are removed
    automatically via ON DELETE CASCADE in the schema.
    """
    denied = authorize_dashboard("delete_docket")
    if denied:
        return denied

    try:
        existing = db_get_report_row(report_id)
        if existing is None:
            return error_response(f"Report '{report_id}' not found", 404)

        supabase.table(REPORTS_TABLE).delete().eq("report_id", report_id).execute()

    except APIError as e:
        return error_response(f"Database error: {e.message if hasattr(e, 'message') else str(e)}", 500)
    except Exception as e:
        return error_response(f"Unexpected server error: {str(e)}", 500)

    return jsonify({"success": True, "deleted": report_id}), 200


# =====================================================================
# AGENT ONBOARDING
# =====================================================================
# The Discord bot already generates every ID (security_id, agreement_id,
# agent_id, clearance_id) itself via the existing /generate/* endpoints
# above. This API does NOT regenerate anything -- it just stores whatever
# the bot already generated and posts in, as each phase completes.
#
# discord_id is the primary key (known from the moment onboarding starts,
# unlike agent_id which doesn't exist until training completes). Every
# onboarding-specific field is nullable until the bot posts it in:
#
#   POST  /agents/create           -> row created with discord_id, status "onboarding"
#   PATCH /agents/<discord_id>/update -> post whitelisted fields as they're
#                                         generated (security_id + agreement_id
#                                         after Phase 2, agent_id + clearance_id +
#                                         clearance_level after training, etc.)
#   GET   /agents/<discord_id>
#   GET   /agents
#
# Per the same rule that governs reports: a write here does NOT create a
# timeline/history event. Onboarding step history lives on Discord and
# stays there -- there is no agents-equivalent timeline table.

AGENT_REQUIRED_CREATE_FIELDS = ["discord_id"]

# Fields the bot is allowed to post in via PATCH /agents/<discord_id>/update.
# All of these are generated/decided elsewhere (the bot's own /generate/*
# calls, or a Lead Agent/Director manually setting clearance_level) --
# this endpoint just stores them.
AGENT_PATCHABLE_FIELDS = {
    "name",
    "status",
    "security_id",
    "agreement_id",
    "agent_id",
    "clearance_level",
    "clearance_id",
}


@app.route("/agents/create", methods=["POST"])
def create_agent():
    """
    Creates the agents row the moment onboarding begins, before Phase 2
    is even done. Only discord_id is required -- everything else gets
    posted in later via /update as the bot generates it.
    """
    denied = authorize_dashboard("manage_agents")
    if denied:
        return denied

    payload = request.get_json(silent=True)
    if payload is None:
        return error_response("Request body must be valid JSON", 400)

    missing = [f for f in AGENT_REQUIRED_CREATE_FIELDS if not str(payload.get(f, "")).strip()]
    if missing:
        return error_response(f"Missing required field(s): {', '.join(missing)}", 400)

    discord_id = str(payload["discord_id"]).strip()

    try:
        existing = db_get_agent_row(discord_id)
        if existing is not None:
            return error_response(f"Agent '{discord_id}' already exists", 409)

        now = _now_iso()
        insert_row = {
            "discord_id": discord_id,
            "name": payload.get("name"),
            "status": payload.get("status", "onboarding"),
            "security_id": None,
            "agreement_id": None,
            "agent_id": None,
            "clearance_level": None,
            "clearance_id": None,
            "created_at": now,
            "updated_at": now,
        }

        supabase.table(AGENTS_TABLE).insert(insert_row).execute()

        agent_obj = fetch_agent_or_raise(discord_id)

    except APIError as e:
        return error_response(f"Database error: {e.message if hasattr(e, 'message') else str(e)}", 500)
    except Exception as e:
        return error_response(f"Unexpected server error: {str(e)}", 500)

    return jsonify({"success": True, "agent": agent_obj}), 201


@app.route("/agents/<discord_id>/update", methods=["PATCH"])
def update_agent(discord_id):
    """
    Posts already-generated fields onto an existing agent row -- e.g. the
    bot calls /generate/join + /generate/agreement after Phase 2, then
    PATCHes security_id/agreement_id here. Same shape later for
    agent_id/clearance_id/clearance_level after training. No generation
    happens in this API; it only stores what's sent.
    """
    denied = authorize_dashboard("manage_agents")
    if denied:
        return denied

    payload = request.get_json(silent=True)
    if payload is None:
        return error_response("Request body must be valid JSON", 400)

    disallowed = [k for k in payload.keys() if k not in AGENT_PATCHABLE_FIELDS]
    if disallowed:
        return error_response(
            f"Field(s) not updatable via /update: {', '.join(disallowed)}.",
            400,
        )

    if not payload:
        return error_response("No updatable fields provided", 400)

    if "clearance_level" in payload and payload["clearance_level"] is not None:
        try:
            level = int(payload["clearance_level"])
        except (TypeError, ValueError):
            return error_response("Field 'clearance_level' must be an integer", 400)
        if level < 1 or level > 5:
            return error_response("Field 'clearance_level' must be between 1 and 5", 400)
        payload["clearance_level"] = level

    try:
        existing = db_get_agent_row(discord_id)
        if existing is None:
            return error_response(f"Agent '{discord_id}' not found", 404)

        changed_fields = [
            field for field, value in payload.items() if existing.get(field) != value
        ]

        if changed_fields:
            now = _now_iso()
            update_data = {field: payload[field] for field in changed_fields}
            update_data["updated_at"] = now

            supabase.table(AGENTS_TABLE).update(update_data).eq(
                "discord_id", discord_id
            ).execute()

        agent_obj = fetch_agent_or_raise(discord_id)

    except AgentNotFound:
        return error_response(f"Agent '{discord_id}' not found", 404)
    except APIError as e:
        return error_response(f"Database error: {e.message if hasattr(e, 'message') else str(e)}", 500)
    except Exception as e:
        return error_response(f"Unexpected server error: {str(e)}", 500)

    return jsonify({"success": True, "agent": agent_obj}), 200


@app.route("/agents/<discord_id>", methods=["GET"])
def get_agent(discord_id):
    denied = authorize_dashboard("view_agents")
    if denied:
        return denied

    try:
        row = db_get_agent_row(discord_id)
        if row is None:
            return error_response(f"Agent '{discord_id}' not found", 404)
        agent_obj = serialize_agent(row)
    except APIError as e:
        return error_response(f"Database error: {e.message if hasattr(e, 'message') else str(e)}", 500)
    except Exception as e:
        return error_response(f"Unexpected server error: {str(e)}", 500)

    return jsonify({"success": True, "agent": agent_obj}), 200


@app.route("/agents", methods=["GET"])
def list_agents():
    """
    List all agents, with optional ?status=onboarding or ?status=active
    filtering. Handy for BotGhost embeds and the dashboard's Agents page.
    """
    denied = authorize_dashboard("view_agents")
    if denied:
        return denied

    status_filter = request.args.get("status")

    try:
        query = supabase.table(AGENTS_TABLE).select("*").order("created_at", desc=True)
        if status_filter:
            query = query.ilike("status", status_filter)
        resp = query.execute()
        rows = resp.data or []
        agents_list = [serialize_agent(row) for row in rows]
    except APIError as e:
        return error_response(f"Database error: {e.message if hasattr(e, 'message') else str(e)}", 500)
    except Exception as e:
        return error_response(f"Unexpected server error: {str(e)}", 500)

    return jsonify({"success": True, "count": len(agents_list), "agents": agents_list}), 200


# =====================
# ERROR HANDLERS
# =====================

@app.errorhandler(404)
def not_found(e):
    return jsonify({"success": False, "error": "Endpoint not found"}), 404


@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({"success": False, "error": "Method not allowed on this endpoint"}), 405


@app.errorhandler(500)
def server_error(e):
    return jsonify({"success": False, "error": "Internal server error"}), 500


if __name__ == "__main__":
    app.run(debug=True)
