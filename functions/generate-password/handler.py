import json
import secrets
import string
import psycopg2
import os
import hashlib


def handle(req):
    try:
        body = json.loads(req) if req else {}
        username = body.get("username")
        if not username:
            return json.dumps({"error": "username required"}), 400

        alphabet = string.ascii_letters + string.digits + string.punctuation
        password = ''.join(secrets.choice(alphabet) for _ in range(16))
        password_hash = hashlib.sha256(password.encode()).hexdigest()

        conn = psycopg2.connect(
            host=os.getenv("DB_HOST", "postgres.database.svc.cluster.local"),
            database=os.getenv("DB_NAME", "cofrapdb"),
            user=os.getenv("DB_USER", "cofrap"),
            password=os.getenv("DB_PASSWORD", "cofrap2026")
        )
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO users (username, password_hash) VALUES (%s, %s) "
            "ON CONFLICT (username) DO UPDATE SET password_hash = EXCLUDED.password_hash",
            (username, password_hash)
        )
        conn.commit()
        cur.close()
        conn.close()

        return json.dumps({"username": username, "password": password})

    except Exception as e:
        return json.dumps({"error": str(e)}), 500
