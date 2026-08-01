from flask import Flask, jsonify, request
import random
import string
import os

app = Flask(__name__)


# =====================
# SECURITY
# =====================

API_KEY = os.environ.get("API_KEY")


def verify_api_key():
    auth = request.headers.get("Authorization")

    if auth != API_KEY:
        return False

    return True


# =====================
# GENERATORS
# =====================

def numbers(amount):
    return ''.join(random.choice(string.digits) for _ in range(amount))


def letters(amount):
    return ''.join(random.choice(string.ascii_uppercase) for _ in range(amount))


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

    return jsonify({
        "code": code
    })


# =====================
# AGENT ID
# =====================

@app.route("/generate/agent")
def agent():

    if not verify_api_key():
        return jsonify({"error": "Unauthorized"}), 401

    code = f"DPS-AG-{numbers(5)}"

    return jsonify({
        "code": code
    })


# =====================
# JOIN CODE
# =====================

@app.route("/generate/join")
def join():

    if not verify_api_key():
        return jsonify({"error": "Unauthorized"}), 401

    code = f"SC-{numbers(3)}{letters(1)}{numbers(1)}"

    return jsonify({
        "code": code
    })


# =====================
# CASE NUMBER
# =====================

@app.route("/generate/case")
def case():

    if not verify_api_key():
        return jsonify({"error": "Unauthorized"}), 401

    code = f"DPS-CASE-{numbers(5)}"

    return jsonify({
        "code": code
    })


# =====================
# INVESTIGATION ID
# =====================

@app.route("/generate/investigation")
def investigation():

    if not verify_api_key():
        return jsonify({"error": "Unauthorized"}), 401

    code = f"INV-{numbers(5)}"

    return jsonify({
        "code": code
    })
