from flask import Flask, g, jsonify, redirect, request, session
import random
import string
import os
import json
import secrets
from datetime import datetime, timezone, timedelta
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
    # Discord returns to this API through a top-level GET redirect. Lax keeps
    # the OAuth state cookie available there without relying on third-party
    # cookie support.
    SESSION_COOKIE_SAMESITE=os.environ.get("SESSION_COOKIE_SAMESITE", "Lax"),
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

# Ranks that are permitted to view and action supervisor reports.
# Anything below Senior Agent is blocked at the API level.
SUPERVISOR_RANKS = {
    "Senior Agent",
    "Head Investigator",
    "Lead Agent",
    "Director",
    "Department Director",
}

# Ranks that are permitted to reassign cases.
REASSIGN_RANKS = {
    "Head Investigator",
    "Lead Agent",
    "Director",
    "Department Director",
}

# Change these values to adjust dashboard access later. Every protected API
# route checks this map, so hiding a button in the UI is never the only guard.
CLEARANCE_POLICY = {
    "view_dashboard": 1,
    "view_agents": 1,
    "view_analytics": 2,
    "add_case_note": 1,
    "add_evidence": 1,
    "manage_dockets": 2,
    "reassign_docket": 4,
    "decide_appeal": 4,
    "manage_agents": 5,
    "delete_docket": 5,
}


def verify_api_key():
    # Cached per-request: several routes check this more than once.
    if "api_key_ok" not in g:
        auth = request.headers.get("Authorization")
        g.api_key_ok = bool(API_KEY) and bool(auth) and secrets.compare_digest(auth, API_KEY)
    return g.api_key_ok


def oauth_configured():
    return all([
        app.config.get("SECRET_KEY"),
        DISCORD_CLIENT_ID,
        DISCORD_CLIENT_SECRET,
        DISCORD_REDIRECT_URI,
        DASHBOARD_ORIGIN,
    ])


def active_agent_from_session():
    """Return the live agent row for this browser session, if eligible.
    Cached per-request so repeated calls cost at most one Supabase read."""
    if "dashboard_agent_row" in g:
        return g.dashboard_agent_row

    discord_id = session.get("discord_id")
    if not discord_id:
        g.dashboard_agent_row = None
        return None

    row = db_get_agent_row(str(discord_id))
    if not row or str(row.get("status") or "").strip().lower() != "active":
        session.clear()
        g.dashboard_agent_row = None
        return None
    g.dashboard_agent_row = row
    return row


def has_permission(agent_row, permission):
    try:
        level = int(agent_row.get("clearance_level"))
    except (TypeError, ValueError):
        return False
    return level >= CLEARANCE_POLICY[permission]


def has_supervisor_access(agent_row):
    """Return True if the agent's rank permits handling supervisor reports."""
    rank = str(agent_row.get("agent_rank") or "").strip()
    return rank in SUPERVISOR_RANKS


def has_reassign_access(agent_row):
    """Return True if the agent's rank permits reassigning cases (Head Investigator+)."""
    rank = str(agent_row.get("agent_rank") or "").strip()
    return rank in REASSIGN_RANKS


def is_assigned_agent(agent_row, report_row):
    """Return True if agent_row is the agent assigned to report_row, or if they
    have supervisor-rank access (they can act on any case)."""
    if has_supervisor_access(agent_row):
        return True
    assigned = str(report_row.get("assigned_agent") or "").strip().lower()
    if not assigned or assigned == "unassigned":
        return False
    candidates = [
        str(agent_row.get("name") or "").strip().lower(),
        str(agent_row.get("agent_id") or "").strip().lower(),
        str(agent_row.get("discord_id") or "").strip().lower(),
    ]
    return any(c and (c == assigned or assigned.startswith(c)) for c in candidates)


def authorize_dashboard(permission):
    """Permit BotGhost's API key or an active, cleared browser session.

    Checks sign-in, clearance level, and — for reassign_docket — that the
    agent holds Head Investigator rank or above.

    Routes that act on a specific report additionally call
    supervisor_report_denied() once the row has been fetched.
    """
    if verify_api_key():
        return None

    agent_row = active_agent_from_session()
    if not agent_row:
        return error_response("Sign-in required", 401)
    if not has_permission(agent_row, permission):
        return error_response("Insufficient clearance", 403)
    if permission == "reassign_docket" and not has_reassign_access(agent_row):
        return error_response("Reassigning cases requires Head Investigator rank or above", 403)
    return None


def supervisor_report_denied(report_row):
    """Row-level gate for supervisor reports. Call after authorize_dashboard()
    has already validated sign-in and clearance for the request."""
    if report_row is None or not report_row.get("is_supervisor"):
        return None
    if verify_api_key() or has_supervisor_access(active_agent_from_session() or {}):
        return None
    return error_response("Supervisor reports require Senior Agent rank or above", 403)


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
PENDING_ACTIONS_TABLE = "pending_actions"
CONTACT_MESSAGES_TABLE = "contact_messages"

# Maximum number of messages allowed in a contact_reporter conversation.
CONTACT_MAX_MESSAGES = 5

# Report actions that require the Discord bot to do follow-up work (DM the
# reporter, adjust roles, post logs). Each one is queued for the bot after
# the API has applied its own state change, so Supabase stays the single
# source of truth and races between Discord and the dashboard resolve to a
# 409 for whichever side loses.
# Action -> (required current status, new status). None means no state change.
REPORT_ACTIONS = {
    "validate":         ("under investigation", "Validated"),
    "invalidate":       ("under investigation", "Invalidated"),
    "investigate":      ("__pre__", "Under Investigation"),
    "contact_reporter": (None, None),
    "claim":            ("open", None),
}

# Statuses an investigation can start from.
_PRE_INVESTIGATION = ("open", "pending")

REQUIRED_CREATE_FIELDS = ["report_id", "reporter", "reported", "reason", "notes", "evidence"]

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
    "is_supervisor",
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
        "report_id": row.get("report_id"),
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
        "agent_rank": row.get("agent_rank"),
        "security_id": row.get("security_id"),
        "agreement_id": row.get("agreement_id"),
        "agent_id": row.get("agent_id"),
        "clearance_level": row.get("clearance_level"),
        "clearance_id": row.get("clearance_id"),
        "created_at": row.get("created_at"),
        "updated_at": row.get("updated_at"),
    }


def build_report_list_item(report_row, agent_name_map=None):
    """
    Lightweight serializer for list endpoints. Does NOT fetch notes/evidence/
    timeline — those are expensive and unused in list views. Agent name
    resolution uses a pre-built map to avoid per-row DB calls.
    """
    assigned_agent = report_row.get("assigned_agent")
    assigned_agent_name = assigned_agent
    if assigned_agent and str(assigned_agent).strip().isdigit():
        assigned_agent_name = (
            (agent_name_map or {}).get(str(assigned_agent).strip())
            or assigned_agent
        )
    return {
        "report_id": report_row["report_id"],
        "reporter": report_row.get("reporter"),
        "reporter_name": report_row.get("reporter_name"),
        "reported": report_row.get("reported"),
        "reported_name": report_row.get("reported_name"),
        "reason": report_row.get("reason"),
        "reporter_notes": report_row.get("notes"),
        "reporter_evidence": report_row.get("evidence"),
        "status": report_row.get("status"),
        "assigned_agent": assigned_agent,
        "assigned_agent_name": assigned_agent_name,
        "notes": [],
        "evidence": [],
        "timeline": [],
        "created_at": report_row.get("created_at"),
        "updated_at": report_row.get("updated_at"),
        "is_supervisor": report_row.get("is_supervisor"),
        "thread_id": report_row.get("thread_id"),
    }


def build_agent_name_map(rows):
    """
    Given a list of report rows, returns a dict of {discord_id: display_name}
    for all rows where assigned_agent looks like a Discord ID. Fetches all
    matching agents in a single query.
    """
    ids = {
        str(r.get("assigned_agent")).strip()
        for r in rows
        if r.get("assigned_agent") and str(r.get("assigned_agent")).strip().isdigit()
    }
    if not ids:
        return {}
    try:
        resp = (
            supabase.table(AGENTS_TABLE)
            .select("discord_id, name, agent_id")
            .in_("discord_id", list(ids))
            .execute()
        )
        return {
            row["discord_id"]: (row.get("name") or row.get("agent_id") or row["discord_id"])
            for row in (resp.data or [])
        }
    except Exception:
        return {}


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

    # Resolve assigned_agent to a display name if it looks like a Discord ID
    # (all digits). Falls back to the raw value if the lookup fails.
    assigned_agent = report_row.get("assigned_agent")
    assigned_agent_name = assigned_agent
    if assigned_agent and str(assigned_agent).strip().isdigit():
        agent_row = db_get_agent_row(str(assigned_agent).strip())
        if agent_row:
            assigned_agent_name = (
                agent_row.get("name")
                or agent_row.get("agent_id")
                or assigned_agent
            )

    return {
        "report_id": report_row["report_id"],
        "reporter": report_row.get("reporter"),
        "reporter_name": report_row.get("reporter_name"),
        "reported": report_row.get("reported"),
        "reported_name": report_row.get("reported_name"),
        "reason": report_row.get("reason"),
        "reporter_notes": report_row.get("notes"),
        "reporter_evidence": report_row.get("evidence"),
        "status": report_row.get("status"),
        "assigned_agent": assigned_agent,
        "assigned_agent_name": assigned_agent_name,
        "notes": [serialize_note(r) for r in notes_rows],
        "evidence": [serialize_evidence(r) for r in evidence_rows],
        "timeline": [serialize_timeline(r) for r in timeline_rows],
        "created_at": report_row.get("created_at"),
        "updated_at": report_row.get("updated_at"),
        "is_supervisor": report_row.get("is_supervisor"),
        "thread_id": report_row.get("thread_id"),
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


def oauth_popup_page(success, error=None):
    """Notify the dashboard opener, then close an OAuth popup window."""
    message = {"type": "ecc-dps-oauth", "success": success}
    if error:
        message["error"] = error
    return (
        "<!doctype html><title>ECC DPS sign-in</title>"
        "<p>Sign-in complete. This window will close automatically.</p>"
        "<script>"
        f"window.opener?.postMessage({json.dumps(message)}, {json.dumps(DASHBOARD_ORIGIN)});"
        "window.close();"
        "</script>",
        200,
        {"Content-Type": "text/html; charset=utf-8"},
    )


def oauth_failure(error):
    if session.pop("oauth_popup", False):
        return oauth_popup_page(False, error)
    return dashboard_redirect("/login", error=error)


def discord_json_request(url, method="GET", data=None):
    headers = {
        "Accept": "application/json",
        # Discord's API (fronted by Cloudflare) rejects the default
        # Python-urllib user-agent. Identify the app explicitly.
        "User-Agent": "ECCDPSDashboard/1.0 (+https://api.eccdps.org)",
    }
    if data is not None:
        data = urlencode(data).encode("utf-8")
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    req = Request(url, data=data, headers=headers, method=method)
    try:
        with urlopen(req, timeout=15) as response:
            return json.loads(response.read().decode("utf-8"))
    except HTTPError as e:
        # Read and re-raise with the Discord error body attached so callers
        # can log or surface the real reason (e.g. invalid_client,
        # redirect_uri_mismatch, invalid_grant).
        body = e.read().decode("utf-8", errors="replace")
        try:
            parsed = json.loads(body)
        except json.JSONDecodeError:
            parsed = {"raw": body}
        raise DiscordAPIError(e.code, parsed) from e


class DiscordAPIError(Exception):
    """Wraps a Discord HTTP error with its parsed JSON body."""
    def __init__(self, status, body):
        self.status = status
        self.body = body
        super().__init__(f"Discord API {status}: {body}")


@app.route("/auth/discord/login", methods=["GET"])
def discord_login():
    if not oauth_configured():
        return error_response("Discord OAuth is not configured", 503)

    state = secrets.token_urlsafe(32)
    session.clear()
    session["oauth_state"] = state
    session["oauth_popup"] = request.args.get("popup") == "1"
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
        return oauth_failure("discord_authorization_denied")

    state = request.args.get("state")
    expected_state = session.pop("oauth_state", None)
    code = request.args.get("code")
    if not code:
        return oauth_failure("missing_oauth_code")
    if not state:
        return oauth_failure("missing_oauth_state")
    if not expected_state:
        return oauth_failure("missing_saved_oauth_state")
    if not secrets.compare_digest(state, expected_state):
        return oauth_failure("oauth_state_mismatch")

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
    except DiscordAPIError as e:
        discord_error = e.body.get("error", "") if isinstance(e.body, dict) else ""
        app.logger.error("Discord token exchange failed (HTTP %s): %s", e.status, e.body)
        if discord_error == "redirect_uri_mismatch":
            return oauth_failure("discord_redirect_uri_mismatch")
        if discord_error in ("invalid_client", "unauthorized_client"):
            return oauth_failure("discord_client_misconfigured")
        return oauth_failure("discord_verification_failed")
    except (URLError, ValueError, json.JSONDecodeError) as e:
        app.logger.error("Discord token exchange error: %s", e)
        return oauth_failure("discord_verification_failed")

    # /users/@me requires the access token; use a separate authenticated call.
    try:
        req = Request(
            "https://discord.com/api/users/@me",
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {access_token}",
                "User-Agent": "ECCDPSDashboard/1.0 (+https://api.eccdps.org)",
            },
        )
        with urlopen(req, timeout=15) as response:
            user = json.loads(response.read().decode("utf-8"))
    except (DiscordAPIError, URLError, json.JSONDecodeError) as e:
        app.logger.error("Discord /users/@me failed: %s", e)
        return oauth_failure("discord_verification_failed")

    discord_id = str(user.get("id", "")).strip()
    agent = db_get_agent_row(discord_id) if discord_id else None
    if not agent:
        return oauth_failure("not_a_dps_agent")
    if str(agent.get("status") or "").strip().lower() != "active":
        return oauth_failure("agent_not_active")

    popup = session.pop("oauth_popup", False)
    session.clear()
    session["discord_id"] = discord_id
    if popup:
        return oauth_popup_page(True)
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
        "can_handle_supervisor": has_supervisor_access(agent),
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
            "reporter_name": str(payload.get("reporter_name", "")).strip() or None,
            "reported": payload["reported"],
            "reported_name": str(payload.get("reported_name", "")).strip() or None,
            "reason": payload["reason"],
            "notes": str(payload["notes"]).strip(),
            "evidence": str(payload["evidence"]).strip(),
            "status": status,
            "assigned_agent": assigned_agent,
            "created_at": now,
            "updated_at": now,
            "is_supervisor": payload.get("is_supervisor", False),
            "thread_id": str(payload["thread_id"]).strip() if payload.get("thread_id") else None,
        }

        supabase.table(REPORTS_TABLE).insert(insert_row).execute()

        # Seed timeline with a "Report created" entry, matching prior behavior.
        supabase.table(TIMELINE_TABLE).insert({
            "report_id": report_id,
            "event": "Report created",
            "by": payload.get("reporter", "Unknown"),
            "created_at": now,
        }).execute()

        # Hard-store the reporter's evidence in public.evidence as well.
        reporter = payload.get("reporter", "Unknown")
        evidence_text = str(payload["evidence"]).strip()
        evidence_url = str(payload.get("evidence_url", "")).strip()

        if evidence_text:
            supabase.table(EVIDENCE_TABLE).insert({
                "report_id": report_id,
                "description": evidence_text,
                "url": evidence_url,
                "submitted_by": reporter,
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
        denied = supervisor_report_denied(row)
        if denied:
            return denied
        report = build_report_json(row)
    except APIError as e:
        return error_response(f"Database error: {e.message if hasattr(e, 'message') else str(e)}", 500)
    except Exception as e:
        return error_response(f"Unexpected server error: {str(e)}", 500)

    return jsonify({"success": True, "report": report}), 200


@app.route("/reports/<report_id>/viewed", methods=["POST"])
def report_viewed(report_id):
    denied = authorize_dashboard("view_dashboard")
    if denied:
        return denied

    row = db_get_report_row(report_id)
    if row is None:
        return error_response(f"Report '{report_id}' not found", 404)

    denied = supervisor_report_denied(row)
    if denied:
        return denied

    agent_session = active_agent_from_session()
    by = (agent_session or {}).get("name") or (agent_session or {}).get("agent_id") or "Dashboard Agent"
    agent_id = (agent_session or {}).get("agent_id") or (agent_session or {}).get("discord_id") or by

    # Deduplicate: only log a "viewed" event if this agent hasn't viewed
    # this report in the last 30 minutes. This prevents spamming the timeline
    # on every page load and avoids the updated_at race condition.
    try:
        now = _now_iso()
        cutoff = (datetime.now(timezone.utc) - timedelta(minutes=30)).isoformat()
        recent = (
            supabase.table(TIMELINE_TABLE)
            .select("id")
            .eq("report_id", report_id)
            .eq("event", "Report viewed in dashboard")
            .eq("by", by)
            .gte("created_at", cutoff)
            .limit(1)
            .execute()
        )
        if not recent.data:
            supabase.table(TIMELINE_TABLE).insert({
                "report_id": report_id,
                "event": "Report viewed in dashboard",
                "by": by,
                "created_at": now,
            }).execute()
            # Only bump updated_at when we actually write an event
            supabase.table(REPORTS_TABLE).update({"updated_at": now}).eq("report_id", report_id).execute()
    except Exception as exc:
        app.logger.warning("Could not write viewed timeline entry: %s", exc)

    return jsonify({"success": True}), 200


@app.route("/evidence", methods=["GET"])
def list_all_evidence():
    """Return all rows from public.evidence, newest first. Used by the Evidence page."""
    denied = authorize_dashboard("view_dashboard")
    if denied:
        return denied
    try:
        resp = (
            supabase.table(EVIDENCE_TABLE)
            .select("*")
            .order("created_at", desc=True)
            .execute()
        )
        rows = resp.data or []
    except APIError as e:
        return error_response(f"Database error: {e.message if hasattr(e, 'message') else str(e)}", 500)
    except Exception as e:
        return error_response(f"Unexpected server error: {str(e)}", 500)
    return jsonify({"success": True, "count": len(rows), "evidence": [serialize_evidence(r) for r in rows]}), 200


@app.route("/reports/<report_id>/evidence/opened", methods=["POST"])
def evidence_opened(report_id):
    denied = authorize_dashboard("view_dashboard")
    if denied:
        return denied

    row = db_get_report_row(report_id)
    if row is None:
        return error_response(f"Report '{report_id}' not found", 404)

    denied = supervisor_report_denied(row)
    if denied:
        return denied

    payload = request.get_json(silent=True) or {}
    description = str(payload.get("description", "Evidence")).strip() or "Evidence"

    agent_session = active_agent_from_session()
    by = (agent_session or {}).get("name") or (agent_session or {}).get("agent_id") or "Dashboard Agent"

    # Write to timeline
    try:
        now = _now_iso()
        supabase.table(TIMELINE_TABLE).insert({
            "report_id": report_id,
            "event": f"Evidence opened: {description[:80]}{'…' if len(description) > 80 else ''}",
            "by": by,
            "created_at": now,
        }).execute()
        supabase.table(REPORTS_TABLE).update({"updated_at": now}).eq("report_id", report_id).execute()
    except Exception as exc:
        app.logger.warning("Could not write evidence_opened timeline entry: %s", exc)

    return jsonify({"success": True}), 200


@app.route("/reports/<report_id>/investigation/begin", methods=["POST"])
def begin_investigation(report_id):
    denied = authorize_dashboard("manage_dockets")
    if denied:
        return denied

    try:
        row = db_get_report_row(report_id)
        if row is None:
            return error_response(f"Report '{report_id}' not found", 404)

        denied = supervisor_report_denied(row)
        if denied:
            return denied

        # Only the assigned agent (or supervisor-rank) can begin an investigation
        agent_session = active_agent_from_session()
        if not verify_api_key() and agent_session and not is_assigned_agent(agent_session, row):
            return error_response("Only the assigned agent can begin the investigation", 403)

        current_status = str(row.get("status") or "").strip().lower()
        if current_status == "under investigation":
            return error_response("Investigation is already in progress", 409)
        if current_status in ("closed", "completed"):
            return error_response("Cannot begin investigation on a closed case", 409)

        agent_session = active_agent_from_session()
        by = (agent_session or {}).get("name") or (agent_session or {}).get("agent_id") or "Dashboard Agent"
        now = _now_iso()

        supabase.table(REPORTS_TABLE).update({
            "status": "Under Investigation",
            "updated_at": now,
        }).eq("report_id", report_id).execute()

        supabase.table(TIMELINE_TABLE).insert({
            "report_id": report_id,
            "event": "Investigation begun",
            "by": by,
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


@app.route("/reports/<report_id>/investigation/end", methods=["POST"])
def end_investigation(report_id):
    denied = authorize_dashboard("manage_dockets")
    if denied:
        return denied

    try:
        row = db_get_report_row(report_id)
        if row is None:
            return error_response(f"Report '{report_id}' not found", 404)

        denied = supervisor_report_denied(row)
        if denied:
            return denied

        # Only the assigned agent (or supervisor-rank) can end an investigation
        agent_session_end = active_agent_from_session()
        if not verify_api_key() and agent_session_end and not is_assigned_agent(agent_session_end, row):
            return error_response("Only the assigned agent can end the investigation", 403)

        current_status = str(row.get("status") or "").strip().lower()
        if current_status != "under investigation":
            return error_response("No investigation is currently in progress", 409)

        agent_session = active_agent_from_session()
        by = (agent_session or {}).get("name") or (agent_session or {}).get("agent_id") or "Dashboard Agent"
        now = _now_iso()

        supabase.table(REPORTS_TABLE).update({
            "status": "Pending",
            "updated_at": now,
        }).eq("report_id", report_id).execute()

        supabase.table(TIMELINE_TABLE).insert({
            "report_id": report_id,
            "event": "Investigation concluded",
            "by": by,
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
    # Determine whether the caller can see supervisor reports
    can_supervisor = verify_api_key() or has_supervisor_access(active_agent_from_session() or {})

    try:
        query = supabase.table(REPORTS_TABLE).select("*").order("created_at", desc=True)
        if status_filter:
            query = query.ilike("status", status_filter)
        resp = query.execute()
        rows = resp.data or []

        # Resolve all Discord IDs to names in a single batch query
        agent_name_map = build_agent_name_map(rows)

        reports = []
        for row in rows:
            if row.get("is_supervisor") and not can_supervisor:
                reports.append({
                    "report_id": row["report_id"],
                    "is_supervisor": True,
                    "restricted": True,
                    "reporter": None,
                    "reported": None,
                    "reason": None,
                    "reporter_notes": None,
                    "reporter_evidence": None,
                    "status": None,
                    "assigned_agent": None,
                    "assigned_agent_name": None,
                    "notes": [],
                    "evidence": [],
                    "timeline": [],
                    "created_at": None,
                    "updated_at": None,
                    "thread_id": None,
                })
            else:
                reports.append(build_report_list_item(row, agent_name_map))
    except APIError as e:
        return error_response(f"Database error: {e.message if hasattr(e, 'message') else str(e)}", 500)
    except Exception as e:
        return error_response(f"Unexpected server error: {str(e)}", 500)

    return jsonify({"success": True, "count": len(reports), "reports": reports}), 200


@app.route("/reports/<report_id>/update", methods=["PATCH"])
def update_report(report_id):
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

    # Reassignment is intentionally stricter than ordinary status/field edits.
    permission = "reassign_docket" if "assigned_agent" in payload else "manage_dockets"
    denied = authorize_dashboard(permission)
    if denied:
        return denied

    try:
        existing = db_get_report_row(report_id)
        if existing is None:
            return error_response(f"Report '{report_id}' not found", 404)

        # Supervisor report rank check
        denied = supervisor_report_denied(existing)
        if denied:
            return denied

        # Assigned-agent-only gate for status and field updates (supervisor ranks bypass)
        if not verify_api_key() and ("status" in payload or "assigned_agent" in payload):
            agent_session_upd = active_agent_from_session()
            if agent_session_upd and not is_assigned_agent(agent_session_upd, existing):
                return error_response("Only the assigned agent can update this case", 403)

        # Status gate: before investigation begins only Open/Pending are allowed
        if not verify_api_key() and "status" in payload:
            current_status = str(existing.get("status") or "").strip().lower()
            new_status = str(payload["status"]).strip()
            pre_investigation = current_status not in ("under investigation",)
            # Also block if investigation was concluded (status = pending/closed/appealed after end)
            allowed_pre = {"Open", "Pending"}
            if pre_investigation and new_status not in allowed_pre:
                return error_response(
                    f"Status can only be set to Open or Pending before an investigation has begun. "
                    f"Start the investigation first to unlock other statuses.",
                    409,
                )

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

            # Build a human-readable timeline event based on what changed
            if changed_fields == ["assigned_agent"]:
                new_assignee = payload.get("assigned_agent") or "Unassigned"
                tl_event = "Assigned agent updated"
                tl_detail = f"Case assigned to: {new_assignee}"
                tl_by = (active_agent_from_session() or {}).get("name") or new_assignee or "System"
            elif changed_fields == ["status"]:
                tl_event = "Status updated"
                tl_detail = f"Status changed to: {payload.get('status', 'Unknown')}"
                tl_by = (active_agent_from_session() or {}).get("name") or "System"
            else:
                tl_event = "Case updated"
                tl_detail = f"Updated: {', '.join(changed_fields)}"
                tl_by = (active_agent_from_session() or {}).get("name") or "System"

            supabase.table(TIMELINE_TABLE).insert({
                "report_id": report_id,
                "event": f"{tl_event}\n{tl_detail}",
                "by": tl_by,
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
    if not verify_api_key():
        agent = active_agent_from_session()
        author = (agent or {}).get("name") or (agent or {}).get("agent_id") or author

    try:
        existing = db_get_report_row(report_id)
        if existing is None:
            return error_response(f"Report '{report_id}' not found", 404)

        denied = supervisor_report_denied(existing)
        if denied:
            return denied

        # Only the assigned agent (or supervisor-rank agents) can add notes
        if not verify_api_key():
            agent_session = active_agent_from_session()
            if agent_session and not is_assigned_agent(agent_session, existing):
                return error_response("Only the assigned agent can add notes to this case", 403)

        if not verify_api_key() and str(existing.get("status") or "").strip().lower() != "under investigation":
            return error_response("Investigation must be started before adding notes", 409)

        now = _now_iso()
        supabase.table(NOTES_TABLE).insert({
            "report_id": report_id,
            "note": note_text,
            "author": author,
            "created_at": now,
        }).execute()

        supabase.table(TIMELINE_TABLE).insert({
            "report_id": report_id,
            "event": f"Note added\n{note_text[:300]}",
            "by": author,
            "created_at": now,
        }).execute()

        supabase.table(REPORTS_TABLE).update({"updated_at": now}).eq("report_id", report_id).execute()

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
    if not verify_api_key():
        agent = active_agent_from_session()
        submitted_by = (agent or {}).get("name") or (agent or {}).get("agent_id") or submitted_by
    url = payload.get("url", "")

    try:
        existing = db_get_report_row(report_id)
        if existing is None:
            return error_response(f"Report '{report_id}' not found", 404)

        denied = supervisor_report_denied(existing)
        if denied:
            return denied

        # Only the assigned agent (or supervisor-rank agents) can add evidence
        if not verify_api_key():
            agent_session = active_agent_from_session()
            if agent_session and not is_assigned_agent(agent_session, existing):
                return error_response("Only the assigned agent can add evidence to this case", 403)

        if not verify_api_key() and str(existing.get("status") or "").strip().lower() != "under investigation":
            return error_response("Investigation must be started before adding evidence", 409)

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
            "event": f"Evidence attached\n{description[:150]} — {url[:200]}",
            "by": submitted_by,
            "created_at": now,
        }).execute()

        supabase.table(REPORTS_TABLE).update({"updated_at": now}).eq("report_id", report_id).execute()

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

        denied = supervisor_report_denied(existing)
        if denied:
            return denied

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

        denied = supervisor_report_denied(existing)
        if denied:
            return denied

        supabase.table(REPORTS_TABLE).delete().eq("report_id", report_id).execute()

    except APIError as e:
        return error_response(f"Database error: {e.message if hasattr(e, 'message') else str(e)}", 500)
    except Exception as e:
        return error_response(f"Unexpected server error: {str(e)}", 500)

    return jsonify({"success": True, "deleted": report_id}), 200


# =====================================================================
# REPORT ACTIONS (validate / invalidate / contact reporter / investigate)
# =====================================================================
# The dashboard exposes the same action buttons as the Discord embed. The
# API applies the state change itself and queues a pending_actions row; the
# Discord bot polls GET /actions/pending on a timer, performs the parts only
# it can do (DMs, role changes, logs), and closes the row via
# POST /actions/<id>/complete.
#
# Because the state transition is guarded here, a Discord button click and a
# dashboard click racing each other resolve cleanly: the first one wins and
# the second gets a 409.

@app.route("/reports/<report_id>/action", methods=["POST"])
def report_action(report_id):
    denied = authorize_dashboard("manage_dockets")
    if denied:
        return denied

    payload = request.get_json(silent=True)
    if payload is None:
        return error_response("Request body must be valid JSON", 400)

    action = str(payload.get("action", "")).strip().lower()
    if action not in REPORT_ACTIONS:
        return error_response(
            f"Unknown action '{action}'. Must be one of: {', '.join(sorted(REPORT_ACTIONS))}",
            400,
        )

    # Optional human-readable reason the agent supplied (e.g. why they're
    # invalidating, or what to investigate). Stored in timeline + queue row.
    reason = str(payload.get("reason", "")).strip() or None

    try:
        row = db_get_report_row(report_id)
        if row is None:
            return error_response(f"Report '{report_id}' not found", 404)

        denied = supervisor_report_denied(row)
        if denied:
            return denied

        # Same actor rules as investigation begin/end: the assigned agent or
        # a supervisor-rank agent (bot API key bypasses).
        agent_session = active_agent_from_session()
        if not verify_api_key() and agent_session and not is_assigned_agent(agent_session, row):
            return error_response("Only the assigned agent can action this case", 403)

        current_status = str(row.get("status") or "").strip().lower()
        required_status, new_status = REPORT_ACTIONS[action]

        # Guard the transition so a duplicate/racing request loses with a 409
        # instead of producing a second result.
        if required_status == "__pre__":
            if current_status == "under investigation":
                return error_response("Investigation is already in progress", 409)
            # Allow reopen only if caller has clearance >= 4
            if current_status in ("closed", "completed", "validated", "invalidated"):
                caller_clearance = int((agent_session or {}).get("clearance_level") or 0)
                if caller_clearance < 4:
                    return error_response("Cannot reopen a concluded investigation without clearance level 4", 403)
        elif required_status is not None:
            if current_status != required_status:
                return error_response(
                    f"'{action}' requires the case to be "
                    f"'{required_status.title()}', but it is currently "
                    f"'{row.get('status') or 'Unknown'}'",
                    409,
                )

        by = (agent_session or {}).get("name") or (agent_session or {}).get("agent_id") or "Dashboard Agent"
        now = _now_iso()

        # Handle claim action: assign the claiming agent to the case
        if action == "claim":
            # Get the agent's Discord ID for assignment
            agent_discord_id = (agent_session or {}).get("discord_id")
            if agent_discord_id:
                supabase.table(REPORTS_TABLE).update({
                    "assigned_agent": agent_discord_id,
                    "updated_at": now,
                }).eq("report_id", report_id).execute()

        if new_status is not None:
            supabase.table(REPORTS_TABLE).update({
                "status": new_status,
                "updated_at": now,
            }).eq("report_id", report_id).execute()

        supabase.table(TIMELINE_TABLE).insert({
            "report_id": report_id,
            "event": {
                "investigate": "Investigation reopened" if current_status in ("closed", "completed", "validated", "invalidated") else "Investigation begun",
                "validate": "Report validated",
                "invalidate": "Report invalidated",
                "contact_reporter": "Reporter contact requested",
                "claim": "Case claimed by agent",
            }[action] + (f" — {reason}" if reason else ""),
            "by": by,
            "created_at": now,
        }).execute()

        # For contact_reporter: write the opening agent message into
        # contact_messages so the dashboard thread card shows message 1/5
        # immediately and unlocks the reply box.
        if action == "contact_reporter":
            opening_body = reason or "An agent has reached out regarding your report and will be in contact shortly."
            supabase.table(CONTACT_MESSAGES_TABLE).insert({
                "report_id": report_id,
                "sender": "agent",
                "sender_name": by,
                "body": opening_body,
                "created_at": now,
            }).execute()

        # Queue the Discord-side work (DM / roles / logging) for the bot.
        queue_resp = (
            supabase.table(PENDING_ACTIONS_TABLE)
            .insert({
                "report_id": report_id,
                "action": action,
                "requested_by": by,
                "reason": reason,
                "status": "pending",
                "created_at": now,
            })
            .execute()
        )

        report = fetch_full_report_or_raise(report_id)

    except ReportNotFound:
        return error_response(f"Report '{report_id}' not found", 404)
    except APIError as e:
        return error_response(f"Database error: {e.message if hasattr(e, 'message') else str(e)}", 500)
    except Exception as e:
        return error_response(f"Unexpected server error: {str(e)}", 500)

    return jsonify({
        "success": True,
        "action": action,
        "queued": True,
        "report": report,
    }), 200


@app.route("/actions/pending", methods=["GET"])
def list_pending_actions():
    """
    Bot-facing queue. Returns pending actions joined with the report basics
    the bot needs to act (thread_id, reporter, reported, reason).
    """
    if not verify_api_key():
        return error_response("Unauthorized", 401)

    try:
        resp = (
            supabase.table(PENDING_ACTIONS_TABLE)
            .select("*, reports(report_id, reporter, reporter_name, reported, reported_name, reason, notes, evidence, created_at, status, assigned_agent, thread_id, is_supervisor)")
            .in_("status", ["pending", "processing"])
            .order("created_at", desc=False)
            .limit(50)
            .execute()
        )
        rows = resp.data or []
    except APIError as e:
        return error_response(f"Database error: {e.message if hasattr(e, 'message') else str(e)}", 500)
    except Exception as e:
        return error_response(f"Unexpected server error: {str(e)}", 500)

    actions = [
        {
            "id": r["id"],
            "report_id": r.get("report_id"),
            "action": r.get("action"),
            "requested_by": r.get("requested_by"),
            "created_at": r.get("created_at"),
            "status": r.get("status"),
            "report": r.get("reports"),
        }
        for r in rows
    ]
    return jsonify({"success": True, "count": len(actions), "actions": actions}), 200


@app.route("/actions/next", methods=["GET"])
def next_pending_action():
    """
    Bot-friendly single-action pickup. Claims the oldest pending action by
    atomically flipping it to 'processing', so two bot ticks never grab
    the same action. Returns 204 with no body when there is nothing to do
    (easy for BotGhost to check: response body empty = go back to sleep).
    """
    if not verify_api_key():
        return error_response("Unauthorized", 401)

    try:
        resp = (
            supabase.table(PENDING_ACTIONS_TABLE)
            .select("*, reports(report_id, reporter, reporter_name, reported, reported_name, reason, notes, evidence, created_at, status, assigned_agent, thread_id, is_supervisor)")
            .eq("status", "pending")
            .order("created_at", desc=False)
            .limit(1)
            .execute()
        )
        rows = resp.data or []
        if not rows:
            return "", 204
    except APIError as e:
        return error_response(f"Database error: {e.message if hasattr(e, 'message') else str(e)}", 500)
    except Exception as e:
        return error_response(f"Unexpected server error: {str(e)}", 500)

    row = rows[0]
    now = _now_iso()
    supabase.table(PENDING_ACTIONS_TABLE).update({
        "status": "processing",
    }).eq("id", row["id"]).execute()

    return jsonify({
        "success": True,
        "id": row["id"],
        "report_id": row.get("report_id"),
        "action": row.get("action"),
        "requested_by": row.get("requested_by"),
        "reason": row.get("reason"),
        "report": row.get("reports"),
    }), 200


@app.route("/actions/<int:action_id>/complete", methods=["POST"])
def complete_action(action_id):
    """
    Bot closes out a queued action. Body: {"result": "success"|"failed",
    "note": optional one-liner about what was done (DM sent, roles changed)}.
    """
    if not verify_api_key():
        return error_response("Unauthorized", 401)

    payload = request.get_json(silent=True)
    if payload is None:
        return error_response("Request body must be valid JSON", 400)

    result = str(payload.get("result", "success")).strip().lower()
    if result not in ("success", "failed"):
        return error_response("Field 'result' must be 'success' or 'failed'", 400)
    note = str(payload.get("note", "")).strip()

    try:
        resp = (
            supabase.table(PENDING_ACTIONS_TABLE)
            .select("*")
            .eq("id", action_id)
            .limit(1)
            .execute()
        )
        rows = resp.data or []
        if not rows:
            return error_response(f"Action '{action_id}' not found", 404)
        row = rows[0]

        if row.get("status") != "pending":
            return error_response(
                f"Action '{action_id}' is already '{row.get('status')}'", 409
            )

        now = _now_iso()
        supabase.table(PENDING_ACTIONS_TABLE).update({
            "status": result,
            "result_note": note or None,
            "completed_at": now,
        }).eq("id", action_id).execute()

        # Audit the bot's completion into the timeline.
        report_row = db_get_report_row(row.get("report_id"))
        if report_row:
            summary = note or f"{row.get('action')} finished ({result})"
            app.logger.info("Action %s completed: %s", action_id, summary)

    except APIError as e:
        return error_response(f"Database error: {e.message if hasattr(e, 'message') else str(e)}", 500)
    except Exception as e:
        return error_response(f"Unexpected server error: {str(e)}", 500)

    return jsonify({"success": True, "completed": action_id, "result": result}), 200


# =====================================================================
# SPLIT QUEUES — supervisor vs operator
# =====================================================================
# Two dedicated single-action pickup endpoints so BotGhost can run two
# separate read-event triggers: one for supervisor cases and one for
# operator cases. Each works identically to /actions/next but filters
# on the linked report's is_supervisor flag.

def _next_action_for_queue(is_supervisor: bool):
    """Shared logic for the supervisor/operator queue pickup endpoints."""
    if not verify_api_key():
        return error_response("Unauthorized", 401)

    try:
        resp = (
            supabase.table(PENDING_ACTIONS_TABLE)
            .select("*, reports(report_id, reporter, reporter_name, reported, reported_name, reason, notes, evidence, created_at, status, assigned_agent, thread_id, is_supervisor)")
            .in_("status", ["pending", "processing"])
            .order("created_at", desc=False)
            .limit(50)
            .execute()
        )
        rows = resp.data or []
        # Filter by is_supervisor on the joined report row
        rows = [
            r for r in rows
            if bool((r.get("reports") or {}).get("is_supervisor")) == is_supervisor
        ]
        if not rows:
            return "", 204
    except APIError as e:
        return error_response(f"Database error: {e.message if hasattr(e, 'message') else str(e)}", 500)
    except Exception as e:
        return error_response(f"Unexpected server error: {str(e)}", 500)

    row = rows[0]
    now = _now_iso()
    supabase.table(PENDING_ACTIONS_TABLE).update({
        "status": "processing",
    }).eq("id", row["id"]).execute()

    return jsonify({
        "success": True,
        "id": row["id"],
        "report_id": row.get("report_id"),
        "action": row.get("action"),
        "requested_by": row.get("requested_by"),
        "reason": row.get("reason"),
        "report": row.get("reports"),
    }), 200


@app.route("/actions/next/operator", methods=["GET"])
def next_operator_action():
    """
    Single-action pickup for the operator queue (non-supervisor reports only).
    BotGhost read-event trigger #1. Returns 204 when queue is empty.
    """
    return _next_action_for_queue(is_supervisor=False)


@app.route("/actions/next/supervisor", methods=["GET"])
def next_supervisor_action():
    """
    Single-action pickup for the supervisor queue (supervisor reports only).
    BotGhost read-event trigger #2. Returns 204 when queue is empty.
    """
    return _next_action_for_queue(is_supervisor=True)


@app.route("/actions/pending/operator", methods=["GET"])
def list_operator_actions():
    """List all pending operator (non-supervisor) actions. Dashboard + bot-facing."""
    if not verify_api_key():
        denied = authorize_dashboard("view_dashboard")
        if denied:
            return denied
    try:
        resp = (
            supabase.table(PENDING_ACTIONS_TABLE)
            .select("*, reports(report_id, reporter, reporter_name, reported, reported_name, reason, notes, evidence, created_at, status, assigned_agent, thread_id, is_supervisor)")
            .in_("status", ["pending", "processing"])
            .order("created_at", desc=False)
            .limit(50)
            .execute()
        )
        rows = [r for r in (resp.data or []) if not bool((r.get("reports") or {}).get("is_supervisor"))]
    except Exception as e:
        return error_response(f"Unexpected server error: {str(e)}", 500)
    actions = [{"id": r["id"], "report_id": r.get("report_id"), "action": r.get("action"),
                "requested_by": r.get("requested_by"), "created_at": r.get("created_at"),
                "status": r.get("status"), "report": r.get("reports")} for r in rows]
    return jsonify({"success": True, "count": len(actions), "actions": actions}), 200


@app.route("/actions/pending/supervisor", methods=["GET"])
def list_supervisor_actions():
    """List all pending supervisor actions. Dashboard + bot-facing."""
    if not verify_api_key():
        denied = authorize_dashboard("view_dashboard")
        if denied:
            return denied
        # Supervisor queue is restricted to Senior Agent rank and above
        agent = active_agent_from_session()
        if not has_supervisor_access(agent or {}):
            return error_response("Supervisor queue requires Senior Agent rank or above", 403)
    try:
        resp = (
            supabase.table(PENDING_ACTIONS_TABLE)
            .select("*, reports(report_id, reporter, reporter_name, reported, reported_name, reason, notes, evidence, created_at, status, assigned_agent, thread_id, is_supervisor)")
            .in_("status", ["pending", "processing"])
            .order("created_at", desc=False)
            .limit(50)
            .execute()
        )
        rows = [r for r in (resp.data or []) if bool((r.get("reports") or {}).get("is_supervisor"))]
    except Exception as e:
        return error_response(f"Unexpected server error: {str(e)}", 500)
    actions = [{"id": r["id"], "report_id": r.get("report_id"), "action": r.get("action"),
                "requested_by": r.get("requested_by"), "created_at": r.get("created_at"),
                "status": r.get("status"), "report": r.get("reports")} for r in rows]
    return jsonify({"success": True, "count": len(actions), "actions": actions}), 200


# =====================================================================
# CONTACT REPORTER CONVERSATION
# =====================================================================
# A capped (5-message) back-and-forth between the assigned agent and the
# reporter, relayed through the Discord bot via DMs.
#
# Flow:
#   1. Agent presses "Contact Reporter" → POST /reports/:id/action with
#      action=contact_reporter (queues bot DM to reporter, inserts first
#      message with sender="agent").
#   2. Reporter DMs the bot back → bot calls POST /reports/:id/contact/respond
#      with {"body": "...", "sender_name": "ReporterName"}.
#   3. Agent replies from the dashboard → POST /reports/:id/contact/reply
#      with {"body": "..."} → queues another bot DM to reporter.
#   4. Repeat up to CONTACT_MAX_MESSAGES total (combined).
#
# GET /reports/:id/contact returns the full thread so the dashboard can
# show the conversation card.
# =====================================================================

def db_get_contact_messages(report_id):
    resp = (
        supabase.table(CONTACT_MESSAGES_TABLE)
        .select("*")
        .eq("report_id", report_id)
        .order("created_at", desc=False)
        .execute()
    )
    return resp.data or []


def serialize_contact_message(row):
    return {
        "id": row.get("id"),
        "sender": row.get("sender"),
        "sender_name": row.get("sender_name"),
        "body": row.get("body"),
        "timestamp": row.get("created_at"),
    }


@app.route("/reports/<report_id>/contact", methods=["GET"])
def get_contact_thread(report_id):
    """Return the contact_reporter conversation for this report."""
    denied = authorize_dashboard("manage_dockets")
    if denied:
        return denied

    try:
        row = db_get_report_row(report_id)
        if row is None:
            return error_response(f"Report '{report_id}' not found", 404)

        denied = supervisor_report_denied(row)
        if denied:
            return denied

        messages = db_get_contact_messages(report_id)
    except APIError as e:
        return error_response(f"Database error: {e.message if hasattr(e, 'message') else str(e)}", 500)
    except Exception as e:
        return error_response(f"Unexpected server error: {str(e)}", 500)

    return jsonify({
        "success": True,
        "report_id": report_id,
        "message_count": len(messages),
        "max_messages": CONTACT_MAX_MESSAGES,
        "messages": [serialize_contact_message(m) for m in messages],
    }), 200


@app.route("/reports/<report_id>/contact/reply", methods=["POST"])
def contact_reply(report_id):
    """
    Dashboard agent sends a follow-up message to the reporter.
    Inserts a contact_message row (sender='agent') and queues a bot DM.
    Blocked once the conversation reaches CONTACT_MAX_MESSAGES.
    """
    denied = authorize_dashboard("manage_dockets")
    if denied:
        return denied

    payload = request.get_json(silent=True)
    if payload is None:
        return error_response("Request body must be valid JSON", 400)

    body = str(payload.get("body", "")).strip()
    if not body:
        return error_response("Field 'body' is required", 400)

    try:
        row = db_get_report_row(report_id)
        if row is None:
            return error_response(f"Report '{report_id}' not found", 404)

        denied = supervisor_report_denied(row)
        if denied:
            return denied

        agent_session = active_agent_from_session()
        if not verify_api_key() and agent_session and not is_assigned_agent(agent_session, row):
            return error_response("Only the assigned agent can contact the reporter", 403)

        messages = db_get_contact_messages(report_id)
        if len(messages) >= CONTACT_MAX_MESSAGES:
            return error_response(
                f"This conversation has reached the {CONTACT_MAX_MESSAGES}-message limit", 409
            )

        by = (agent_session or {}).get("name") or (agent_session or {}).get("agent_id") or "DPS Agent"
        now = _now_iso()

        supabase.table(CONTACT_MESSAGES_TABLE).insert({
            "report_id": report_id,
            "sender": "agent",
            "sender_name": by,
            "body": body,
            "created_at": now,
        }).execute()

        supabase.table(TIMELINE_TABLE).insert({
            "report_id": report_id,
            "event": f"Agent message sent to reporter ({len(messages) + 1}/{CONTACT_MAX_MESSAGES})",
            "by": by,
            "created_at": now,
        }).execute()

        supabase.table(REPORTS_TABLE).update({"updated_at": now}).eq("report_id", report_id).execute()

        # Queue a bot DM to the reporter.
        remaining = CONTACT_MAX_MESSAGES - (len(messages) + 1)
        supabase.table(PENDING_ACTIONS_TABLE).insert({
            "report_id": report_id,
            "action": "contact_reporter",
            "requested_by": by,
            "reason": body,
            "status": "pending",
            "created_at": now,
        }).execute()

        messages = db_get_contact_messages(report_id)

    except APIError as e:
        return error_response(f"Database error: {e.message if hasattr(e, 'message') else str(e)}", 500)
    except Exception as e:
        return error_response(f"Unexpected server error: {str(e)}", 500)

    return jsonify({
        "success": True,
        "message_count": len(messages),
        "max_messages": CONTACT_MAX_MESSAGES,
        "messages": [serialize_contact_message(m) for m in messages],
    }), 201


@app.route("/reports/<report_id>/contact/respond", methods=["POST"])
def contact_respond(report_id):
    """
    Bot relays the reporter's DM reply back into the conversation.
    Called by BotGhost when the reporter DMs the bot in response.
    Body: {"body": "...", "sender_name": "DiscordUsername"}
    Bot API key required.
    """
    if not verify_api_key():
        return error_response("Unauthorized", 401)

    payload = request.get_json(silent=True)
    if payload is None:
        return error_response("Request body must be valid JSON", 400)

    body = str(payload.get("body", "")).strip()
    sender_name = str(payload.get("sender_name", "Reporter")).strip() or "Reporter"
    if not body:
        return error_response("Field 'body' is required", 400)

    try:
        row = db_get_report_row(report_id)
        if row is None:
            return error_response(f"Report '{report_id}' not found", 404)

        messages = db_get_contact_messages(report_id)
        if len(messages) >= CONTACT_MAX_MESSAGES:
            return error_response(
                f"This conversation has reached the {CONTACT_MAX_MESSAGES}-message limit", 409
            )

        now = _now_iso()

        supabase.table(CONTACT_MESSAGES_TABLE).insert({
            "report_id": report_id,
            "sender": "reporter",
            "sender_name": sender_name,
            "body": body,
            "created_at": now,
        }).execute()

        supabase.table(TIMELINE_TABLE).insert({
            "report_id": report_id,
            "event": f"Reporter replied ({len(messages) + 1}/{CONTACT_MAX_MESSAGES})",
            "by": sender_name,
            "created_at": now,
        }).execute()

        supabase.table(REPORTS_TABLE).update({"updated_at": now}).eq("report_id", report_id).execute()

        messages = db_get_contact_messages(report_id)

    except APIError as e:
        return error_response(f"Database error: {e.message if hasattr(e, 'message') else str(e)}", 500)
    except Exception as e:
        return error_response(f"Unexpected server error: {str(e)}", 500)

    return jsonify({
        "success": True,
        "message_count": len(messages),
        "max_messages": CONTACT_MAX_MESSAGES,
        "messages": [serialize_contact_message(m) for m in messages],
    }), 201


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
    "agent_rank",
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
            "agent_rank": payload.get("agent_rank", None),
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

    VALID_RANKS = {
        "Trial Agent", "Probationary Agent", "Agent", "Senior Agent",
        "Head Investigator", "Lead Agent", "Director", "Department Director",
    }
    if "agent_rank" in payload and payload["agent_rank"] is not None:
        if str(payload["agent_rank"]).strip() not in VALID_RANKS:
            return error_response(
                f"Invalid agent_rank. Must be one of: {', '.join(sorted(VALID_RANKS))}",
                400,
            )

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
