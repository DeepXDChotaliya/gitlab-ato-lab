"""
Password-Reset Type-Confusion Lab
==================================
Recreates the class of bug behind the GitLab HackerOne report #2293343
("Account Takeover via Password Reset without user interaction", $35,000
bounty, CWE-843 Access of Resource Using Incompatible Type).

THE BUG (as reported):
  The password-reset endpoint expected `email` to be a single string.
  Because the backend parsed JSON loosely, an attacker could submit
  `"email": ["victim@site.com", "attacker@site.com"]` instead of a
  single string. The backend happily looked up the victim by the first
  address, then mailed the reset link to EVERY address in the array -
  including the attacker's own inbox. Net result: attacker gets a
  valid password-reset token for the victim's account, with zero
  interaction from the victim.

THIS LAB:
  - Real Flask backend, real session-based login, real SQLite DB.
  - No outbound email (this sandbox has no SMTP egress) - instead each
    address has a fake "mailbox" you view in the browser, exactly like
    Mailtrap/Mailhog would in a real test environment. Swap in real
    SMTP later if you want (see README).
  - A VULN_MODE toggle (/toggle-mode) so you can demo the bug, flip
    the switch, and demo the fix live on camera without restarting.

HOW TO ATTACK IT (mirrors the real report):
  1. Register two accounts: victim@example.com and attacker@example.com
  2. Log out. Go to /forgot-password, submit victim@example.com normally
     first (this is what a legit request looks like).
  3. Intercept the POST to /forgot-password in Burp. It's a JSON body:
         {"email": "victim@example.com"}
  4. In Burp, change it to an array with the attacker's address added:
         {"email": ["victim@example.com", "attacker@example.com"]}
  5. Forward it. In VULN_MODE, both mailboxes receive the SAME reset
     token, tied to the victim's account.
  6. Open /mailbox/attacker@example.com, click the reset link, set a
     new password. You are now the victim.
  7. Flip VULN_MODE off at /toggle-mode and repeat step 4-6 to show it
     now gets rejected with a 400.

Run: python3 app.py   -> http://127.0.0.1:5000
"""

import os
import sqlite3
import secrets
import time
from flask import Flask, request, render_template, redirect, url_for, session, g, jsonify, flash

DB_PATH = os.path.join(os.path.dirname(__file__), "lab.db")

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# ---------------------------------------------------------------------------
# Global demo toggle. In a real app this would never be a runtime switch -
# it's here purely so you can show "vulnerable" vs "patched" behaviour in
# the same recording without restarting the server.
# ---------------------------------------------------------------------------
VULN_MODE = {"on": True}


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DB_PATH)
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS reset_tokens (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            created_at INTEGER NOT NULL,
            used INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS mailbox (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            to_address TEXT NOT NULL,
            subject TEXT NOT NULL,
            body TEXT NOT NULL,
            created_at INTEGER NOT NULL
        );
        """
    )
    db.commit()
    db.close()


def send_mail(to_address, subject, body):
    """Fake mail transport: just writes a row into the mailbox table."""
    db = get_db()
    db.execute(
        "INSERT INTO mailbox (to_address, subject, body, created_at) VALUES (?, ?, ?, ?)",
        (to_address, subject, body, int(time.time())),
    )
    db.commit()


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------
def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    return get_db().execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()


from werkzeug.security import generate_password_hash, check_password_hash


# ---------------------------------------------------------------------------
# Routes: register / login / dashboard
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    return redirect(url_for("dashboard") if current_user() else url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        if not email or not password:
            flash("Email and password required.")
            return redirect(url_for("register"))
        db = get_db()
        try:
            db.execute(
                "INSERT INTO users (email, password_hash) VALUES (?, ?)",
                (email, generate_password_hash(password)),
            )
            db.commit()
        except sqlite3.IntegrityError:
            flash("That email is already registered.")
            return redirect(url_for("register"))
        flash("Account created. Log in.")
        return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = get_db().execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            return redirect(url_for("dashboard"))
        flash("Invalid credentials.")
        return redirect(url_for("login"))
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/dashboard")
def dashboard():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    return render_template("dashboard.html", user=user, vuln_on=VULN_MODE["on"])


@app.route("/toggle-mode")
def toggle_mode():
    VULN_MODE["on"] = not VULN_MODE["on"]
    return redirect(request.referrer or url_for("dashboard"))


# ---------------------------------------------------------------------------
# The vulnerable / patched endpoint
# ---------------------------------------------------------------------------
@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "GET":
        return render_template("forgot.html", vuln_on=VULN_MODE["on"])

    # Accept JSON (what Burp will manipulate) or a normal form post.
    if request.is_json:
        data = request.get_json(silent=True) or {}
    else:
        data = request.form

    email_field = data.get("email")

    db = get_db()

    if VULN_MODE["on"]:
        # --- VULNERABLE BEHAVIOUR -------------------------------------
        # No type check. If `email` is a list, treat every element as a
        # delivery address, but resolve the ACCOUNT from the first
        # element only. This is exactly the GitLab bug: the token is
        # scoped to the victim, but delivery goes to every address the
        # attacker listed.
        if isinstance(email_field, list):
            recipients = [str(e).strip().lower() for e in email_field if e]
        else:
            recipients = [str(email_field).strip().lower()] if email_field else []

        if not recipients:
            return jsonify({"error": "email required"}), 400

        lookup_email = recipients[0]  # account is resolved from the FIRST address
        user = db.execute("SELECT * FROM users WHERE email = ?", (lookup_email,)).fetchone()

        if user:
            token = secrets.token_urlsafe(24)
            db.execute(
                "INSERT INTO reset_tokens (token, user_id, created_at) VALUES (?, ?, ?)",
                (token, user["id"], int(time.time())),
            )
            db.commit()
            reset_link = url_for("reset_password", token=token, _external=True)
            for addr in recipients:
                send_mail(
                    addr,
                    "Reset your password",
                    f"A password reset was requested for {user['email']}.\n"
                    f"Reset link: {reset_link}",
                )
        # Always return the same generic response, whether or not the
        # user existed - real password-reset flows should never leak
        # account existence. (The GitLab bug lived one level deeper
        # than this check, which is exactly why it slipped through.)
        return jsonify({"message": "If that account exists, a reset link has been sent."})

    else:
        # --- PATCHED BEHAVIOUR ------------------------------------------
        # Strict type check: email must be a plain string. Anything else
        # (list, dict, int...) is rejected outright with 400, before any
        # DB lookup or mail dispatch happens.
        if not isinstance(email_field, str):
            return jsonify({"error": "email must be a string"}), 400

        lookup_email = email_field.strip().lower()
        if not lookup_email:
            return jsonify({"error": "email required"}), 400

        user = db.execute("SELECT * FROM users WHERE email = ?", (lookup_email,)).fetchone()
        if user:
            token = secrets.token_urlsafe(24)
            db.execute(
                "INSERT INTO reset_tokens (token, user_id, created_at) VALUES (?, ?, ?)",
                (token, user["id"], int(time.time())),
            )
            db.commit()
            reset_link = url_for("reset_password", token=token, _external=True)
            # Patched version mails ONLY the account's own registered address.
            send_mail(
                user["email"],
                "Reset your password",
                f"A password reset was requested for your account.\nReset link: {reset_link}",
            )
        return jsonify({"message": "If that account exists, a reset link has been sent."})


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    db = get_db()
    row = db.execute(
        "SELECT * FROM reset_tokens WHERE token = ? AND used = 0", (token,)
    ).fetchone()

    if not row:
        return render_template("reset.html", valid=False), 400

    # Tokens tied to user_id only - this part matches real behaviour and
    # is NOT the bug. The bug is entirely in who gets *told* the token.
    if request.method == "POST":
        new_password = request.form.get("password", "")
        if len(new_password) < 6:
            flash("Password too short.")
            return redirect(url_for("reset_password", token=token))
        db.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (generate_password_hash(new_password), row["user_id"]),
        )
        db.execute("UPDATE reset_tokens SET used = 1 WHERE token = ?", (token,))
        db.commit()
        flash("Password updated. Log in with your new password.")
        return redirect(url_for("login"))

    return render_template("reset.html", valid=True, token=token)


# ---------------------------------------------------------------------------
# Fake mailbox viewer - stands in for an SMTP catcher like Mailhog/Mailtrap
# ---------------------------------------------------------------------------
@app.route("/mailbox/<address>")
def mailbox(address):
    db = get_db()
    mails = db.execute(
        "SELECT * FROM mailbox WHERE to_address = ? ORDER BY created_at DESC",
        (address.strip().lower(),),
    ).fetchall()
    return render_template("mailbox.html", address=address, mails=mails)


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5000, debug=True)
