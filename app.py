from dotenv import load_dotenv
load_dotenv()

import io
import base64
import os

import pymysql
import pyotp
import qrcode
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "local-dev-secret-key")

APP_NAME = "QR-Auth-Demo"

MYSQL_CONFIG = {
    "host": os.environ.get("DB_HOST", "localhost"),
    "port": int(os.environ.get("DB_PORT", 3306)),
    "user": os.environ.get("DB_USER", "root"),
    "password": os.environ.get("DB_PASSWORD", "your_mysql_password"),
    "database": os.environ.get("DB_NAME", "qr_auth"),
    "cursorclass": pymysql.cursors.DictCursor
}

# DB helpers
def get_db():
    return pymysql.connect(**MYSQL_CONFIG)

def init_db():
    conn = get_db()
    with conn.cursor() as cursor:
        cursor.execute("""CREATE TABLE IF NOT EXISTS users(id INT AUTO_INCREMENT PRIMARY KEY, username VARCHAR(100) UNIQUE NOT NULL, password_hash VARCHAR(255) NOT NULL, totp_secret VARCHAR(32) NOT NULL)
                    """)
    conn.commit()
    conn.close()

# routes
@app.route("/")
def home():
    return render_template("home.html", user=session.get("user"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]

        if not username or not password:
            flash("Username and Password are required.")
            return redirect(url_for("register"))

        conn = get_db()
        with conn.cursor() as cursor:
            cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
            existing = cursor.fetchone()

            if existing:
                conn.close()
                flash("That username is already taken.")
                return redirect(url_for("register"))

            password_hash = generate_password_hash(password)
            totp_secret = pyotp.random_base32()

            cursor.execute(
                "INSERT INTO users (username, password_hash, totp_secret) VALUES (%s, %s, %s)",
                (username, password_hash, totp_secret),
            )
        conn.commit()
        conn.close()

        return redirect(url_for("show_qr", username=username))

    return render_template("register.html")


@app.route("/show_qr/<username>")
def show_qr(username):
    conn = get_db()
    with conn.cursor() as cursor:
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()
    conn.close()
    if user is None:
        flash("User Not Found.")
        return redirect(url_for("register"))

    totp = pyotp.TOTP(user["totp_secret"])
    otp_uri = totp.provisioning_uri(name=username, issuer_name=APP_NAME)

    qr_img = qrcode.make(otp_uri)
    buffer = io.BytesIO()
    qr_img.save(buffer, format="PNG")
    qr_base64 = base64.b64encode(buffer.getvalue()).decode("utf-8")
    return render_template("show_qr.html", username=username, qr_base64=qr_base64)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]

        conn = get_db()
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
            user = cursor.fetchone()
        conn.close()

        if user is None or not check_password_hash(user["password_hash"], password):
            flash("Invalid Username or Password.")
            return redirect(url_for("login"))

        session["pending_user"] = username
        return redirect(url_for("verify"))

    return render_template("login.html")


@app.route("/verify", methods=["GET", "POST"])
def verify():
    username = session.get("pending_user")
    if not username:
        flash("Please login with your username and password first.")
        return redirect(url_for("login"))

    if request.method == "POST":
        code = request.form['otp'].strip()

        conn = get_db()
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
            user = cursor.fetchone()
        conn.close()

        totp = pyotp.TOTP(user["totp_secret"])

        if totp.verify(code):
            session.pop("pending_user", None)
            session["user"] = username
            flash("Login Succesful")
            return redirect(url_for("dashboard"))
        else:
            flash("Incorrect or Expired code. Try again.")
            return redirect(url_for("verify"))

    return render_template("verify.html", username=username)


@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        flash("Please log in first.")
        return redirect(url_for("login"))
    return render_template("dashboard.html", user=session["user"])


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.")
    return redirect(url_for("home"))


if __name__ == "__main__":
    init_db()
    app.run(debug=True)