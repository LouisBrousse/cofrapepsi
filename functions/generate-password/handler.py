import json
import secrets
import string
import psycopg2
import os
import hashlib


def handle(event, context):
    try:
        body = json.loads(event.body) if event.body else {}
        username = body.get("username")
        if not username:
            return {"statusCode": 400, "body": json.dumps({"error": "username required"})}

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

        return {"statusCode": 200, "body": json.dumps({"username": username, "password": password})}

    except Exception as e:
        return {"statusCode": 500, "body": json.dumps({"error": str(e)})}
