import json
import pyotp
import psycopg2
import os
import base64
import io
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
            "totp_uri": totp_uri,
            "qr_code": qr_b64
        })}

    except Exception as e:
        return {"statusCode": 500, "body": json.dumps({"error": str(e)})}
