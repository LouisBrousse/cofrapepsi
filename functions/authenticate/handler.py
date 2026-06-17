import json
import re
import psycopg2
import pyotp
import os
import time
from cryptography.fernet import Fernet

SIX_MONTHS_SECONDS = 6 * 30 * 24 * 3600
USERNAME_RE = re.compile(r'^[a-zA-Z0-9._-]{1,50}$')
TOTP_RE = re.compile(r'^\d{6}$')


def get_fernet():
    with open("/var/openfaas/secrets/fernet-key", "r") as f:
        key = f.read().strip().encode()
    return Fernet(key)


def handle(event, context):
    try:
        body = json.loads(event.body) if event.body else {}
        username = body.get("username", "")
        password = body.get("password", "")
        totp_code = body.get("totp_code", "")

        if not USERNAME_RE.match(str(username)):
            return {"statusCode": 400, "body": json.dumps({"error": "invalid input"})}

        if not password or len(str(password)) > 128:
            return {"statusCode": 400, "body": json.dumps({"error": "invalid input"})}

        if not TOTP_RE.match(str(totp_code)):
            return {"statusCode": 400, "body": json.dumps({"error": "invalid input"})}

        conn = psycopg2.connect(
            host=os.getenv("DB_HOST", "postgres.database.svc.cluster.local"),
            database=os.getenv("DB_NAME", "cofrapdb"),
            user=os.getenv("DB_USER", "cofrap"),
            password=os.getenv("DB_PASSWORD", "cofrap2026")
        )
        cur = conn.cursor()
        cur.execute(
            "SELECT password_hash, totp_secret, gendate, expired FROM users WHERE username = %s",
            (username,)
        )
        row = cur.fetchone()

        if not row:
            cur.close()
            conn.close()
            return {"statusCode": 401, "body": json.dumps({"authenticated": False, "error": "identifiants incorrects"})}

        encrypted_password, encrypted_totp, gendate, expired = row

        if expired:
            cur.close()
            conn.close()
            return {"statusCode": 401, "body": json.dumps({
                "authenticated": False,
                "error": "account expired",
                "action": "renew"
            })}

        now = int(time.time())
        if gendate and (now - gendate) > SIX_MONTHS_SECONDS:
            cur.execute("UPDATE users SET expired = TRUE WHERE username = %s", (username,))
            conn.commit()
            cur.close()
            conn.close()
            return {"statusCode": 401, "body": json.dumps({
                "authenticated": False,
                "error": "credentials expired",
                "action": "renew"
            })}

        f = get_fernet()
        try:
            decrypted_password = f.decrypt(encrypted_password.encode()).decode()
        except Exception:
            cur.close()
            conn.close()
            return {"statusCode": 401, "body": json.dumps({"authenticated": False, "error": "identifiants incorrects"})}

        if decrypted_password != password:
            cur.close()
            conn.close()
            return {"statusCode": 401, "body": json.dumps({"authenticated": False, "error": "identifiants incorrects"})}

        try:
            decrypted_totp = f.decrypt(encrypted_totp.encode()).decode()
        except Exception:
            cur.close()
            conn.close()
            return {"statusCode": 401, "body": json.dumps({"authenticated": False, "error": "identifiants incorrects"})}

        totp = pyotp.TOTP(decrypted_totp)
        if not totp.verify(totp_code, valid_window=1):
            cur.close()
            conn.close()
            return {"statusCode": 401, "body": json.dumps({"authenticated": False, "error": "identifiants incorrects"})}

        cur.close()
        conn.close()
        return {"statusCode": 200, "body": json.dumps({"authenticated": True, "username": username})}

    except Exception:
        return {"statusCode": 500, "body": json.dumps({"error": "internal server error"})}
