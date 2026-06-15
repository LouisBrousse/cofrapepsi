import json
import psycopg2
import pyotp
import os
import hashlib


def handle(req):
    try:
        body = json.loads(req) if req else {}
        username = body.get("username")
        password = body.get("password")
        totp_code = body.get("totp_code")

        if not username or not password or not totp_code:
            return json.dumps({"error": "username, password and totp_code required"}), 400

        conn = psycopg2.connect(
            host=os.getenv("DB_HOST", "postgres.database.svc.cluster.local"),
            database=os.getenv("DB_NAME", "cofrapdb"),
            user=os.getenv("DB_USER", "cofrap"),
            password=os.getenv("DB_PASSWORD", "cofrap2026")
        )
        cur = conn.cursor()
        cur.execute(
            "SELECT password_hash, totp_secret FROM users WHERE username = %s",
            (username,)
        )
        row = cur.fetchone()
        cur.close()
        conn.close()

        if not row:
            return json.dumps({"authenticated": False, "error": "user not found"}), 401

        password_hash, totp_secret = row
        input_hash = hashlib.sha256(password.encode()).hexdigest()

        if input_hash != password_hash:
            return json.dumps({"authenticated": False, "error": "invalid password"}), 401

        totp = pyotp.TOTP(totp_secret)
        if not totp.verify(totp_code):
            return json.dumps({"authenticated": False, "error": "invalid totp code"}), 401

        return json.dumps({"authenticated": True, "username": username})

    except Exception as e:
        return json.dumps({"error": str(e)}), 500
