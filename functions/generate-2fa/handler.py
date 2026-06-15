import json
import pyotp
import psycopg2
import os


def handle(req):
    try:
        body = json.loads(req) if req else {}
        username = body.get("username")
        if not username:
            return json.dumps({"error": "username required"}), 400

        totp_secret = pyotp.random_base32()

        conn = psycopg2.connect(
            host=os.getenv("DB_HOST", "postgres.database.svc.cluster.local"),
            database=os.getenv("DB_NAME", "cofrapdb"),
            user=os.getenv("DB_USER", "cofrap"),
            password=os.getenv("DB_PASSWORD", "cofrap2026")
        )
        cur = conn.cursor()
        cur.execute(
            "UPDATE users SET totp_secret = %s WHERE username = %s",
            (totp_secret, username)
        )
        conn.commit()
        cur.close()
        conn.close()

        totp_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(
            name=username, issuer_name="COFRAP"
        )

        return json.dumps({"username": username, "totp_secret": totp_secret, "totp_uri": totp_uri})

    except Exception as e:
        return json.dumps({"error": str(e)}), 500
