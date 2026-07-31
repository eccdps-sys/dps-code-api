from flask import Flask, jsonify
import random
import string

app = Flask(__name__)


def numbers(amount):
    return ''.join(random.choice(string.digits) for _ in range(amount))


def letters(amount):
    return ''.join(random.choice(string.ascii_uppercase) for _ in range(amount))


@app.route("/")
def home():
    return "DPS API Online"


# Agreement Code
@app.route("/generate/agreement")
def agreement():
    code = f"AGM-{numbers(4)}"

    return jsonify({
        "code": code
    })


# Agent ID
@app.route("/generate/agent")
def agent():
    code = f"DPS-AG-{numbers(5)}"

    return jsonify({
        "code": code
    })


# Security Join Code
@app.route("/generate/join")
def join():
    code = f"SC-{numbers(3)}{letters(1)}{numbers(1)}"

    return jsonify({
        "code": code
    })


# Case Number
@app.route("/generate/case")
def case():
    code = f"DPS-CASE-{numbers(5)}"

    return jsonify({
        "code": code
    })


# Investigation Number
@app.route("/generate/investigation")
def investigation():
    code = f"INV-{numbers(5)}"

    return jsonify({
        "code": code
    })


app.run(host="0.0.0.0", port=5000)