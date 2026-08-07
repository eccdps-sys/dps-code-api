from flask import Flask, jsonify, request
import random
import string
import os
import json
import tempfile
import time
import errno
from datetime import datetime, timezone
from contextlib import contextmanager

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


# =====================
# REPORT STORAGE CONFIG
# =====================
DATA_DIR = os.environ.get("DPS_DATA_DIR", os.path.join(os.path.dirname(os.path.abspath(__file__)), "data"))
REPORTS_FILE = os.path.join(DATA_DIR, "reports.json")
LOCK_FILE = REPORTS_FILE + ".lock"

os.makedirs(DATA_DIR, exist_ok=True)


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def _load_reports():
    """Load the reports JSON file, creating it if it doesn't exist."""
    if not os.path.exists(REPORTS_FILE):
        return {}
    try:
        with open(REPORTS_FILE, "r", encoding="utf-8") as f:
            content = f.read().strip()
            if not content:
                return {}
            return json.loads(content)
    except json.JSONDecodeError:
        # Corrupt file - don't silently wipe data, surface it instead.
        raise RuntimeError("reports.json is corrupted and could not be parsed")


def _save_reports(reports):
    """
    Atomically write the reports dict back to disk.
    Writes to a temp file then renames, so a crash mid-write can't corrupt
    the store.
    """
    dir_name = os.path.dirname(REPORTS_FILE)
    fd, tmp_path = tempfile.mkstemp(dir=dir_name, prefix=".reports_", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(reports, f, indent=2, ensure_ascii=False)
        os.replace(tmp_path, REPORTS_FILE)
    except Exception:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        raise


class LockTimeout(Exception):
    pass


@contextmanager
def with_reports_lock(timeout=10, poll_interval=0.05):
    """
    A minimal cross-request file lock using atomic exclusive file creation
    (O_CREAT | O_EXCL). No third-party dependency required.

    This guards against two simultaneous requests (e.g. two BotGhost
    commands firing at once) reading, modifying, and writing reports.json
    in a way that clobbers each other's changes.
    """
    deadline = time.time() + timeout
    fd = None
    while True:
        try:
            fd = os.open(LOCK_FILE, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            break
        except OSError as e:
            if e.errno != errno.EEXIST:
                raise
            if time.time() >= deadline:
                raise LockTimeout("Timed out waiting for reports.json lock")
            time.sleep(poll_interval)
    try:
        yield
    finally:
        os.close(fd)
        try:
            os.remove(LOCK_FILE)
        except OSError:
            pass


REQUIRED_CREATE_FIELDS = ["report_id", "reporter", "subject", "reason"]

# Fields that BotGhost/clients are allowed to directly overwrite via PATCH.
# notes/evidence/timeline are intentionally excluded - those are append-only
# via their dedicated endpoints, so a PATCH can't accidentally wipe history.
PATCHABLE_FIELDS = {
    "reporter",
    "subject",
    "reason",
    "status",
    "assigned_agent",
}


def new_report_shell(data):
    """Builds the stored record for a new report from the incoming payload."""
    return {
        "report_id": data["report_id"],
        "reporter": data["reporter"],
        "subject": data["subject"],
        "reason": data["reason"],
        "status": data.get("status", "Open"),
        "assigned_agent": data.get("assigned_agent", "Unassigned"),
        "notes": [],
        "evidence": [],
        "timeline": [
            {
                "event": "Report created",
                "by": data.get("reporter", "Unknown"),
                "timestamp": _now_iso(),
            }
        ],
        "created_at": _now_iso(),
        "updated_at": _now_iso(),
    }


def error_response(message, status_code):
    return jsonify({"success": False, "error": message}), status_code


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

    try:
        with with_reports_lock():
            reports = _load_reports()

            if report_id in reports:
                return error_response(f"Report '{report_id}' already exists", 409)

            record = new_report_shell({**payload, "report_id": report_id})
            reports[report_id] = record
            _save_reports(reports)
    except LockTimeout:
        return error_response("Server busy, please retry", 503)
    except RuntimeError as e:
        return error_response(str(e), 500)

    return jsonify({"success": True, "report": record}), 201


@app.route("/reports/<report_id>", methods=["GET"])
def get_report(report_id):
    if not verify_api_key():
        return error_response("Unauthorized", 401)

    try:
        with with_reports_lock():
            reports = _load_reports()
    except RuntimeError as e:
        return error_response(str(e), 500)

    report = reports.get(report_id)
    if report is None:
        return error_response(f"Report '{report_id}' not found", 404)

    return jsonify({"success": True, "report": report}), 200


@app.route("/reports", methods=["GET"])
def list_reports():
    """
    Optional convenience endpoint: list all reports, with optional
    ?status=Open filtering. Handy for BotGhost embeds that show open cases.
    """
    if not verify_api_key():
        return error_response("Unauthorized", 401)

    try:
        with with_reports_lock():
            reports = _load_reports()
    except RuntimeError as e:
        return error_response(str(e), 500)

    status_filter = request.args.get("status")
    values = list(reports.values())
    if status_filter:
        values = [r for r in values if r.get("status", "").lower() == status_filter.lower()]

    return jsonify({"success": True, "count": len(values), "reports": values}), 200


@app.route("/reports/<report_id>/update", methods=["PATCH"])
def update_report(report_id):
    if not verify_api_key():
        return error_response("Unauthorized", 401)

    payload = request.get_json(silent=True)
    if payload is None:
        return error_response("Request body must be valid JSON", 400)

    # Reject attempts to overwrite append-only or protected fields directly.
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
        with with_reports_lock():
            reports = _load_reports()
            report = reports.get(report_id)
            if report is None:
                return error_response(f"Report '{report_id}' not found", 404)

            changed_fields = []
            for field, value in payload.items():
                if report.get(field) != value:
                    report[field] = value
                    changed_fields.append(field)

            if changed_fields:
                report["updated_at"] = _now_iso()
                report["timeline"].append({
                    "event": f"Updated field(s): {', '.join(changed_fields)}",
                    "by": payload.get("assigned_agent") or "System",
                    "timestamp": _now_iso(),
                })
                reports[report_id] = report
                _save_reports(reports)
    except LockTimeout:
        return error_response("Server busy, please retry", 503)
    except RuntimeError as e:
        return error_response(str(e), 500)

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
        with with_reports_lock():
            reports = _load_reports()
            report = reports.get(report_id)
            if report is None:
                return error_response(f"Report '{report_id}' not found", 404)

            entry = {
                "note": note_text,
                "author": author,
                "timestamp": _now_iso(),
            }
            report["notes"].append(entry)
            report["updated_at"] = _now_iso()
            report["timeline"].append({
                "event": f"Note added by {author}",
                "by": author,
                "timestamp": _now_iso(),
            })
            reports[report_id] = report
            _save_reports(reports)
    except LockTimeout:
        return error_response("Server busy, please retry", 503)
    except RuntimeError as e:
        return error_response(str(e), 500)

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
        with with_reports_lock():
            reports = _load_reports()
            report = reports.get(report_id)
            if report is None:
                return error_response(f"Report '{report_id}' not found", 404)

            entry = {
                "description": description,
                "url": url,
                "submitted_by": submitted_by,
                "timestamp": _now_iso(),
            }
            report["evidence"].append(entry)
            report["updated_at"] = _now_iso()
            report["timeline"].append({
                "event": f"Evidence added by {submitted_by}",
                "by": submitted_by,
                "timestamp": _now_iso(),
            })
            reports[report_id] = report
            _save_reports(reports)
    except LockTimeout:
        return error_response("Server busy, please retry", 503)
    except RuntimeError as e:
        return error_response(str(e), 500)

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
        with with_reports_lock():
            reports = _load_reports()
            report = reports.get(report_id)
            if report is None:
                return error_response(f"Report '{report_id}' not found", 404)

            entry = {
                "event": event_text,
                "by": by,
                "timestamp": _now_iso(),
            }
            report["timeline"].append(entry)
            report["updated_at"] = _now_iso()
            reports[report_id] = report
            _save_reports(reports)
    except LockTimeout:
        return error_response("Server busy, please retry", 503)
    except RuntimeError as e:
        return error_response(str(e), 500)

    return jsonify({"success": True, "event": entry, "report": report}), 201


@app.route("/reports/<report_id>", methods=["DELETE"])
def delete_report(report_id):
    """
    Optional: hard-delete a report. Not required by the spec, but included
    since case management systems usually need a way to remove bad/test
    entries. Gate this hard behind your API key.
    """
    if not verify_api_key():
        return error_response("Unauthorized", 401)

    try:
        with with_reports_lock():
            reports = _load_reports()
            if report_id not in reports:
                return error_response(f"Report '{report_id}' not found", 404)
            removed = reports.pop(report_id)
            _save_reports(reports)
    except LockTimeout:
        return error_response("Server busy, please retry", 503)
    except RuntimeError as e:
        return error_response(str(e), 500)

    return jsonify({"success": True, "deleted": removed["report_id"]}), 200


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
