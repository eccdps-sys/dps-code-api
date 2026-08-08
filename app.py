from flask import Flask, jsonify, request
import random
import string
import os
from datetime import datetime, timezone
from postgrest.exceptions import APIError
from supabase import create_client, Client

app = Flask(__name__)

# =====================
# SECURITY
# (unchanged from the original app.py)
# =====================
API_KEY = os.environ.get("API_KEY")


def verify_api_key():
    auth = request.headers.get("Authorization")
    if auth != API_KEY:
        return False
    return True


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

REQUIRED_CREATE_FIELDS = ["report_id", "reporter", "reason"]

# Fields that BotGhost/clients are allowed to directly overwrite via PATCH.
# notes/evidence/timeline stay append-only via their dedicated endpoints,
# so a PATCH can't accidentally wipe history.
PATCHABLE_FIELDS = {
    "reporter",
    "notes",
    "reason",
    "status",
    "assigned_agent",
}


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def error_response(message, status_code):
    return jsonify({"success": False, "error": message}), status_code


class ReportNotFound(Exception):
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
        "reason": report_row.get("reason"),
        "status": report_row.get("status"),
        "assigned_agent": report_row.get("assigned_agent"),
        "notes": [serialize_note(r) for r in notes_rows],
        "evidence": [serialize_evidence(r) for r in evidence_rows],
        "timeline": [serialize_timeline(r) for r in timeline_rows],
        "created_at": report_row.get("created_at"),
        "updated_at": report_row.get("updated_at"),
    }


def fetch_full_report_or_raise(report_id):
    row = db_get_report_row(report_id)
    if row is None:
        raise ReportNotFound(report_id)
    return build_report_json(row)


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
    if not verify_api_key():
        return error_response("Unauthorized", 401)

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
            "reason": payload["reason"],
            "notes": "",
            "evidence": "",
            "status": status,
            "assigned_agent": assigned_agent,
            "created_at": now,
            "updated_at": now,
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
    if not verify_api_key():
        return error_response("Unauthorized", 401)

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
    if not verify_api_key():
        return error_response("Unauthorized", 401)

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
    if not verify_api_key():
        return error_response("Unauthorized", 401)

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
    if not verify_api_key():
        return error_response("Unauthorized", 401)

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
    if not verify_api_key():
        return error_response("Unauthorized", 401)

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
    if not verify_api_key():
        return error_response("Unauthorized", 401)

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
    if not verify_api_key():
        return error_response("Unauthorized", 401)

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
