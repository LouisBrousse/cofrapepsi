from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory
import requests
import os

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET", "cofrap-dev-secret")

GATEWAY = os.getenv("OPENFAAS_GATEWAY", "http://gateway.openfaas.svc.cluster.local:8080")
GW_USER = os.getenv("OPENFAAS_USER", "admin")
GW_PASS = os.getenv("OPENFAAS_PASS", "")


def call_function(name, payload):
    url = f"{GATEWAY}/function/{name}"
    resp = requests.post(url, json=payload, auth=(GW_USER, GW_PASS), timeout=30)
    return resp.status_code, resp.json()

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        if not username:
            return render_template("register.html", error="Nom d'utilisateur requis")

        status, data = call_function("generate-password", {"username": username})
        if status != 200:
            return render_template("register.html", error=data.get("error", "Erreur serveur"))

        session["reg_username"] = username
        session["reg_password"] = data.get("password")
        return render_template("register_password.html",
                               username=username,
                               password=data.get("password"),
                               qr_code=data.get("qr_code"))

    return render_template("register.html")


@app.route("/register/2fa", methods=["POST"])
def register_2fa():
    username = session.get("reg_username")
    if not username:
        return redirect(url_for("register"))

    status, data = call_function("generate-2fa", {"username": username})
    if status != 200:
        return render_template("register_password.html", error=data.get("error", "Erreur serveur"))

    return render_template("register_2fa.html",
                           username=username,
                           totp_uri=data.get("totp_uri"),
                           qr_code=data.get("qr_code"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        totp_code = request.form.get("totp_code", "").strip()

        status, data = call_function("authenticate", {
            "username": username,
            "password": password,
            "totp_code": totp_code
        })

        if status == 200 and data.get("authenticated"):
            session["user"] = username
            return redirect(url_for("dashboard"))

        if data.get("action") == "renew":
            session["reg_username"] = username
            return redirect(url_for("register"))

        return render_template("login.html", error=data.get("error", "Authentification échouée"))

    return render_template("login.html")


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
