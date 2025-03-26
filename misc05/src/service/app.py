import os
import string
import secrets
from flask import Flask, render_template, jsonify, request
import psycopg
import requests

DB_HOST = os.getenv("POSTGRES_HOST", "db")
DB_PORT = int(os.getenv("POSTGRES_PORT", "5432"))
DB_NAME = os.getenv("POSTGRES_DB", "postfix")
DB_USER = os.getenv("POSTGRES_USER")
DB_PASS = os.getenv("POSTGRES_PASSWORD")
EMAIL_DOMAIN = os.getenv("EMAIL_DOMAIN")
TURNSTILE_SITE_KEY = os.getenv("TURNSTILE_SITE_KEY")
TURNSTILE_SECRET_KEY = os.getenv("TURNSTILE_SECRET_KEY")

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('index.html', domain=EMAIL_DOMAIN, turnstile_site_key=TURNSTILE_SITE_KEY)

@app.route('/add', methods=['POST'])
def add_user():
    try:
        body = request.get_json(silent=True) or {}
        token = body.get('turnstileToken')
        if not (TURNSTILE_SECRET_KEY and TURNSTILE_SITE_KEY):
            return jsonify({"error": "Turnstile not configured"}), 500
        if not token:
            return jsonify({"error": "Captcha token missing"}), 400
        verify_resp = requests.post(
            'https://challenges.cloudflare.com/turnstile/v0/siteverify',
            data={
                'secret': TURNSTILE_SECRET_KEY,
                'response': token,
                'remoteip': request.remote_addr,
            },
            timeout=5,
        )
        vr = verify_resp.json()
        if not vr.get('success'):
            return jsonify({"error": "Captcha verification failed"}), 400
    except Exception as e:
        return jsonify({"error": f"Captcha error: {e}"}), 500

    alphabet = string.ascii_lowercase + string.digits
    tries, max_tries = 0, 5

    try:
        with psycopg.connect(
            host=DB_HOST,
            port=DB_PORT,
            dbname=DB_NAME,
            user=DB_USER,
            password=DB_PASS,
        ) as conn:
            with conn.cursor() as cur:
                while tries < max_tries:
                    tries += 1
                    username = "user-" + "".join(secrets.choice(alphabet) for _ in range(8))
                    password = "".join(secrets.choice(alphabet + string.ascii_letters) for _ in range(16))

                    cur.execute(
                        """
                        INSERT INTO mailbox (username, domain, password)
                        VALUES (%s, %s, %s)
                        ON CONFLICT (username, domain) DO NOTHING
                        RETURNING username
                        """,
                        (username, EMAIL_DOMAIN, password),
                    )
                    row = cur.fetchone()
                    if row:
                        conn.commit()
                        return jsonify(
                            {
                                "username": username,
                                "domain": EMAIL_DOMAIN,
                                "password": password,
                            }
                        ), 201

                return jsonify({"error": "Could not generate a unique username"}), 409

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.get('/healthz')
def healthz():
    return "ok", 200