from flask import Flask, render_template, request
import re
import sqlite3
from datetime import datetime
import os

app = Flask(__name__)


# ---------------- DATABASE SETUP ----------------
def init_db():
    conn = sqlite3.connect("history.db")
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT,
            result TEXT,
            risk TEXT,
            score INTEGER,
            confidence INTEGER,
            time TEXT
        )
    """)
    conn.commit()
    conn.close()

init_db()


# ---------------- SAVE SCAN ----------------
def save_scan(email, result, risk, score, confidence):
    conn = sqlite3.connect("history.db")
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO scans (email, result, risk, score, confidence, time)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (email[:200], result, risk, score, confidence, str(datetime.now())))
    conn.commit()
    conn.close()


# ---------------- FAKE DOMAIN DETECTION ----------------
def detect_fake_domain(text):

    suspicious_tlds = [".xyz", ".top", ".ru", ".click", ".online", ".site"]
    fake_brands = ["google", "amazon", "paypal", "bank", "apple", "microsoft"]

    found = []

    urls = re.findall(r'(https?://[^\s]+)', text.lower())

    for url in urls:
        for tld in suspicious_tlds:
            if tld in url:
                found.append("Suspicious domain extension detected")

        for brand in fake_brands:
            if brand in url and ("-" in url or "login" in url or "verify" in url):
                found.append("Fake brand impersonation detected")

        if any(char.isdigit() for char in url):
            found.append("Suspicious numeric pattern in domain")

    return found


# ---------------- URGENCY DETECTION ----------------
def detect_urgency(text):

    urgency_words = [
        "urgent", "immediately", "act now", "account blocked",
        "within 24 hours", "verify now", "final warning",
        "limited time", "quick action"
    ]

    return ["Urgency-based social engineering detected"] if any(w in text for w in urgency_words) else []


# ---------------- HOME ----------------
@app.route("/")
def home():
    return render_template("index.html")


# ---------------- CHECK EMAIL ----------------
@app.route("/check", methods=["POST"])
def check():

    email = request.form.get("email", "")
    text = email.lower()

    keywords = ["won", "bank", "otp", "password", "click", "verify"]
    found = []

    if email.strip() == "":
        return render_template(
            "index.html",
            result="⚠ Please enter an email.",
            reasons=[],
            explanation=[],
            risk="NONE",
            score=0,
            confidence=0,
            total=0,
            phishing=0,
            safe=0
        )

    # keyword detection
    for w in keywords:
        if w in text:
            found.append("Suspicious keyword detected: " + w)

    # link detection
    if "http://" in text or "https://" in text:
        found.append("Suspicious link detected")

    # fake domain
    found.extend(detect_fake_domain(text))

    # urgency
    found.extend(detect_urgency(text))

    # SAFE CASE
    if len(found) == 0:
        result = "🟢 Safe Email"
        risk = "LOW"
        score = 10
        confidence = 90
    else:
        result = "🔴 Phishing Email Detected!"
        score = min(100, len(found) * 12)
        confidence = min(99, 50 + len(found) * 8)

        if len(found) >= 6:
            risk = "HIGH"
        elif len(found) >= 3:
            risk = "MEDIUM"
        else:
            risk = "LOW"


    # ---------------- SAVE HISTORY ----------------
    save_scan(email, result, risk, score, confidence)


    # ---------------- STATS ----------------
    conn = sqlite3.connect("history.db")
    cur = conn.cursor()

    cur.execute("SELECT COUNT(*) FROM scans")
    total = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM scans WHERE result LIKE '%Phishing%'")
    phishing = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM scans WHERE result LIKE '%Safe%'")
    safe = cur.fetchone()[0]

    conn.close()


    # ---------------- AI EXPLANATION ----------------
    explanation = []
    for f in found:
        explanation.append("Detected pattern: " + f)


    return render_template(
        "index.html",
        result=result,
        reasons=found,
        explanation=explanation,
        risk=risk,
        score=score,
        confidence=confidence,
        total=total,
        phishing=phishing,
        safe=safe
    )


# ---------------- HISTORY PAGE ----------------
@app.route("/history")
def history():

    conn = sqlite3.connect("history.db")
    cur = conn.cursor()
    cur.execute("""
        SELECT email, result, risk, score, confidence, time
        FROM scans ORDER BY id DESC
    """)
    data = cur.fetchall()
    conn.close()

    return render_template("history.html", data=data)


# ---------------- DEPLOYMENT START ----------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)