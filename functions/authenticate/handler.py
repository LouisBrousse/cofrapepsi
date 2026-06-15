import json
import psycopg2
import pyotp
import os
import time
from cryptography.fernet import Fernet


FERNET_KEY = os.getenv("FERNET_KEY", "").encode()
SIX_MONTHS_SECONDS = 6 * 30 * 24 * 3600


def get_fernet():
    return Fernet(FERNET_KEY)


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
            "SELECT password_hash, totp_secret, gendate, expired FROM users WHERE username = %s",
            (username,)
        )
        row = cur.fetchone()

        if not row:
            cur.close()
            conn.close()
            return {"statusCode": 401, "body": json.dumps({"authenticated": False, "error": "user not found"})}

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
            return {"statusCode": 500, "body": json.dumps({"error": "decryption error"})}

        if decrypted_password != password:
            cur.close()
            conn.close()
            return {"statusCode": 401, "body": json.dumps({"authenticated": False, "error": "invalid password"})}

        try:
            decrypted_totp = f.decrypt(encrypted_totp.encode()).decode()
        except Exception:
            cur.close()
            conn.close()
            return {"statusCode": 500, "body": json.dumps({"error": "decryption error"})}

        totp = pyotp.TOTP(decrypted_totp)
        if not totp.verify(totp_code):
            cur.close()
            conn.close()
            return {"statusCode": 401, "body": json.dumps({"authenticated": False, "error": "invalid totp code"})}

        cur.close()
        conn.close()
        return {"statusCode": 200, "body": json.dumps({"authenticated": True, "username": username})}

    except Exception as e:
        return {"statusCode": 500, "body": json.dumps({"error": str(e)})}
