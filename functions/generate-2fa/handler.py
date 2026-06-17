import json
import re
import pyotp
import psycopg2
import os
import base64
import io
import qrcode
from cryptography.fernet import Fernet

USERNAME_RE = re.compile(r'^[a-zA-Z0-9._-]{1,50}$')


def get_fernet():
    with open("/var/openfaas/secrets/fernet-key", "r") as f:
        key = f.read().strip().encode()
    return Fernet(key)


def handle(event, context):
    try:
        body = json.loads(event.body) if event.body else {}
        username = body.get("username", "")

        if not USERNAME_RE.match(str(username)):
            return {"statusCode": 400, "body": json.dumps({"error": "invalid username"})}

        totp_secret = pyotp.random_base32()
        f = get_fernet()
        encrypted_secret = f.encrypt(totp_secret.encode()).decode()

        totp_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(
            name=username, issuer_name="COFRAP"
        )
        img = qrcode.make(totp_uri)
        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        qr_b64 = base64.b64encode(buffer.getvalue()).decode()

        conn = psycopg2.connect(
            host=os.getenv("DB_HOST", "postgres.database.svc.cluster.local"),
            database=os.getenv("DB_NAME", "cofrapdb"),
            user=os.getenv("DB_USER", "cofrap"),
            password=os.getenv("DB_PASSWORD", "cofrap2026")
        )
        cur = conn.cursor()
        cur.execute(
            "UPDATE users SET totp_secret = %s WHERE username = %s",
            (encrypted_secret, username)
        )
        conn.commit()
        cur.close()
        conn.close()

        return {"statusCode": 200, "body": json.dumps({
            "username": username,
            "totp_secret": totp_secret,
            "totp_uri": totp_uri,
            "qr_code": qr_b64
        })}

    except Exception:
        return {"statusCode": 500, "body": json.dumps({"error": "internal server error"})}
