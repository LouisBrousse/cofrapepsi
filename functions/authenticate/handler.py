import json
import psycopg2
import pyotp
import os
import hashlib


def handle(event, context):
    try:
        body = json.loads(event.body) if event.body else {}
        username = body.get("username")
        password = body.get("password")
        totp_code = body.get("totp_code")

        if not username or not password or not totp_code:
            return {"statusCode": 400, "body": json.dumps({"error": "username, password and totp_code required"})}

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
            return {"statusCode": 401, "body": json.dumps({"authenticated": False, "error": "user not found"})}

        password_hash, totp_secret = row
        input_hash = hashlib.sha256(password.encode()).hexdigest()

        if input_hash != password_hash:
            return {"statusCode": 401, "body": json.dumps({"authenticated": False, "error": "invalid password"})}

        totp = pyotp.TOTP(totp_secret)
        if not totp.verify(totp_code):
            return {"statusCode": 401, "body": json.dumps({"authenticated": False, "error": "invalid totp code"})}

        return {"statusCode": 200, "body": json.dumps({"authenticated": True, "username": username})}

    except Exception as e:
        return {"statusCode": 500, "body": json.dumps({"error": str(e)})}
