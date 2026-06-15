import json
import secrets
import string
import psycopg2
import os
import base64
import io
import time
import qrcode
from cryptography.fernet import Fernet


FERNET_KEY = os.getenv("FERNET_KEY", "").encode()


def get_fernet():
    return Fernet(FERNET_KEY)


def handle(event, context):
    try:
        body = json.loads(event.body) if event.body else {}
        username = body.get("username")
        if not username:
            return {"statusCode": 400, "body": json.dumps({"error": "username required"})}

        alphabet = string.ascii_uppercase + string.ascii_lowercase + string.digits + string.punctuation
        while True:
            password = ''.join(secrets.choice(alphabet) for _ in range(24))
            has_upper = any(c in string.ascii_uppercase for c in password)
            has_lower = any(c in string.ascii_lowercase for c in password)
            has_digit = any(c in string.digits for c in password)
            has_special = any(c in string.punctuation for c in password)
            if has_upper and has_lower and has_digit and has_special:
                break

        f = get_fernet()
        encrypted_password = f.encrypt(password.encode()).decode()

        img = qrcode.make(password)
        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        qr_b64 = base64.b64encode(buffer.getvalue()).decode()

        gendate = int(time.time())

        conn = psycopg2.connect(
            host=os.getenv("DB_HOST", "postgres.database.svc.cluster.local"),
            database=os.getenv("DB_NAME", "cofrapdb"),
            user=os.getenv("DB_USER", "cofrap"),
            password=os.getenv("DB_PASSWORD", "cofrap2026")
        )
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO users (username, password_hash, gendate, expired) VALUES (%s, %s, %s, FALSE) "
            "ON CONFLICT (username) DO UPDATE SET password_hash = EXCLUDED.password_hash, "
            "gendate = EXCLUDED.gendate, expired = FALSE",
            (username, encrypted_password, gendate)
        )
        conn.commit()
        cur.close()
        conn.close()

        return {"statusCode": 200, "body": json.dumps({
            "username": username,
            "password": password,
            "qr_code": qr_b64
        })}

    except Exception as e:
        return {"statusCode": 500, "body": json.dumps({"error": str(e)})}
