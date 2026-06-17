import re
from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import requests
import os

app = Flask(__name__)
app.secret_key = os.environ["FLASK_SECRET"]

csrf = CSRFProtect(app)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[],
    storage_uri="memory://"
)

GATEWAY = os.getenv("OPENFAAS_GATEWAY", "http://gateway.openfaas.svc.cluster.local:8080")
GW_USER = os.getenv("OPENFAAS_USER", "admin")
GW_PASS = os.getenv("OPENFAAS_PASS", "")

USERNAME_RE = re.compile(r'^[a-zA-Z0-9._-]{1,50}$')
TOTP_RE = re.compile(r'^\d{6}$')


@app.after_request
def set_security_headers(response):
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "script-src 'none';"
    )
    return response


def call_function(name, payload):
    url = f"{GATEWAY}/function/{name}"
    resp = requests.post(url, json=payload, auth=(GW_USER, GW_PASS), timeout=30)
    return resp.status_code, resp.json()


def validate_username(username):
    if not username or not USERNAME_RE.match(username):
        return False
    return True


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        if not validate_username(username):
            return render_template("register.html", error="Nom d'utilisateur invalide (1-50 caractères alphanumériques, . _ -)")

        status, data = call_function("generate-password", {"username": username})
        if status != 200:
            return render_template("register.html", error="Erreur lors de la création du compte.")

        session["reg_username"] = username
        return render_template("register_password.html",
                               username=username,
                               password=data.get("password"),
                               qr_code=data.get("qr_code"))

    return render_template("register.html")


@app.route("/register/2fa", methods=["POST"])
@limiter.limit("10 per minute")
def register_2fa():
    username = session.get("reg_username")
    if not username:
        return redirect(url_for("register"))

    status, data = call_function("generate-2fa", {"username": username})
    if status != 200:
        return render_template("register_password.html", error="Erreur lors de la configuration 2FA.")

    return render_template("register_2fa.html",
                           username=username,
                           totp_secret=data.get("totp_secret"),
                           totp_uri=data.get("totp_uri"),
                           qr_code=data.get("qr_code"))


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        totp_code = request.form.get("totp_code", "").strip()

        if not validate_username(username):
            return render_template("login.html", error="Identifiants incorrects.")

        if not TOTP_RE.match(totp_code):
            return render_template("login.html", error="Le code 2FA doit être composé de 6 chiffres.")

        if not password:
            return render_template("login.html", error="Identifiants incorrects.")

        status, data = call_function("authenticate", {
            "username": username,
            "password": password,
            "totp_code": totp_code
        })

        if status == 200 and data.get("authenticated"):
            session["user"] = username
            return redirect(url_for("dashboard"))

        if data.get("action") == "renew":
            session["renew_username"] = username
            return redirect(url_for("renew"))

        return render_template("login.html", error="Identifiants ou code 2FA incorrects.")

    return render_template("login.html")


@app.route("/renew", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def renew():
    username = session.get("renew_username")
    if not username:
        return redirect(url_for("login"))

    if request.method == "POST":
        status, data = call_function("generate-password", {"username": username})
        if status != 200:
            return render_template("renew_expired.html", username=username,
                                   error="Erreur lors du renouvellement.")
        return render_template("renew_password.html",
                               username=username,
                               password=data.get("password"),
                               qr_code=data.get("qr_code"))

    return render_template("renew_expired.html", username=username)


@app.route("/renew/2fa", methods=["POST"])
@limiter.limit("10 per minute")
def renew_2fa():
    username = session.get("renew_username")
    if not username:
        return redirect(url_for("login"))

    status, data = call_function("generate-2fa", {"username": username})
    if status != 200:
        return render_template("renew_password.html", username=username,
                               error="Erreur lors de la configuration 2FA.")

    session.pop("renew_username", None)
    return render_template("register_2fa.html",
                           username=username,
                           totp_secret=data.get("totp_secret"),
                           totp_uri=data.get("totp_uri"),
                           qr_code=data.get("qr_code"))


@app.route("/dashboard")
def dashboard():
    user = session.get("user")
    if not user:
        return redirect(url_for("login"))
    return render_template("dashboard.html", username=user)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
