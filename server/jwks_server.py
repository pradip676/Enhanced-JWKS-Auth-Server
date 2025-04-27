import os
import base64
import datetime
import sqlite3
from time import time
from collections import deque
from threading import Lock

from flask import Flask, request, jsonify, make_response
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import jwt
from cryptography.hazmat.primitives import serialization

from .db_manager import (
    setup_database,
    generate_and_save_keys,
    get_rsa_key,
    fetch_valid_keys,
    aes_decrypt,
    AES_KEY
)


app = Flask(__name__)


class TimeWindowRateLimiter:
    def __init__(self, max_requests, time_window):
        self.max_requests = max_requests
        self.time_window = time_window
        self.requests = {}  # Track requests per IP
        self.lock = Lock()

    def allow_request(self, ip):
        current_time = time()
        with self.lock:
            if ip not in self.requests:
                self.requests[ip] = deque()

            request_times = self.requests[ip]

            # Remove old timestamps outside the window
            while request_times and (current_time - request_times[0]) > self.time_window:
                request_times.popleft()

            if len(request_times) < self.max_requests:
                request_times.append(current_time)
                return True
            else:
                return False


auth_limiter = TimeWindowRateLimiter(max_requests=10, time_window=1)
ph = PasswordHasher()


def create_users_table():
    with sqlite3.connect("totally_not_my_privateKeys.db") as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                email TEXT UNIQUE,
                date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP
            )
        """)
        conn.commit()


def create_auth_logs_table():
    with sqlite3.connect("totally_not_my_privateKeys.db") as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS auth_logs(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_ip TEXT NOT NULL,
                request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                user_id INTEGER,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        """)
        conn.commit()


# Initialize database structure
setup_database()
create_users_table()
create_auth_logs_table()
generate_and_save_keys()


@app.route("/register", methods=["POST"])
def register():
    data = request.json or {}
    username = data.get("username")
    email = data.get("email")

    if not username:
        return jsonify({"error": "Username is required"}), 400

    password = str(os.urandom(16).hex())
    password_hash = ph.hash(password)

    try:
        with sqlite3.connect("totally_not_my_privateKeys.db") as conn:
            conn.execute(
                """
                INSERT INTO users (username, password_hash, email)
                VALUES (?, ?, ?)
                """,
                (username, password_hash, email)
            )
            conn.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "Username or email already exists"}), 409

    return jsonify({"password": password}), 201


@app.route("/auth", methods=["POST"])
def auth_user():
    if not auth_limiter.allow_request(request.remote_addr):
        return jsonify({"error": "Too Many Requests"}), 429

    data = request.json or {}
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    with sqlite3.connect("totally_not_my_privateKeys.db") as conn:
        cursor = conn.execute(
            "SELECT id, password_hash FROM users WHERE username = ?",
            (username,)
        )
        row = cursor.fetchone()
        user_id = row[0] if row else None
        conn.execute(
            "INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)",
            (request.remote_addr, user_id)
        )
        conn.commit()

    if not row:
        return jsonify({"error": "Invalid credentials"}), 401

    try:
        stored_hash = row[1]
        ph.verify(stored_hash, password)
    except VerifyMismatchError:
        return jsonify({"error": "Invalid credentials"}), 401

    with sqlite3.connect("totally_not_my_privateKeys.db") as conn:
        conn.execute(
            "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?",
            (user_id,)
        )
        conn.commit()

    use_expired = (request.args.get("expired", "false").lower() == "true")
    kid, private_key = get_rsa_key(get_expired=use_expired)

    if not private_key:
        return jsonify({"error": "No appropriate key found"}), 404

    now = datetime.datetime.now(datetime.timezone.utc)
    exp_time = (
        now - datetime.timedelta(minutes=30)
        if use_expired else now + datetime.timedelta(minutes=30)
    )

    payload = {
        "sub": username,
        "iat": now,
        "exp": exp_time
    }

    token = jwt.encode(
        payload,
        private_key,
        algorithm="RS256",
        headers={"kid": str(kid)}
    )

    return jsonify({"token": token}), 200


@app.route('/.well-known/jwks.json', methods=['GET'])
def serve_jwks():
    jwks_keys = []
    valid_keys = fetch_valid_keys()

    for kid, encrypted_data in valid_keys:
        pem_data = aes_decrypt(encrypted_data, AES_KEY)
        private_key = serialization.load_pem_private_key(
            pem_data,
            password=None
        )
        public_numbers = private_key.public_key().public_numbers()
        n_bytes = public_numbers.n.to_bytes(
            (public_numbers.n.bit_length() + 7) // 8, 'big'
        )
        e_bytes = public_numbers.e.to_bytes(
            (public_numbers.e.bit_length() + 7) // 8, 'big'
        )

        jwks_keys.append({
            'kid': str(kid),
            'kty': 'RSA',
            'alg': 'RS256',
            'use': 'sig',
            'n': base64.urlsafe_b64encode(n_bytes).decode().rstrip('='),
            'e': base64.urlsafe_b64encode(e_bytes).decode().rstrip('=')
        })

    return jsonify({'keys': jwks_keys})


@app.route('/auth', methods=['GET', 'PUT', 'DELETE', 'PATCH'])
def auth_invalid():
    return make_response(jsonify({'message': 'Method Not Allowed'}), 405)


@app.route(
    '/.well-known/jwks.json',
    methods=['POST', 'PUT', 'DELETE', 'PATCH']
)
def jwks_invalid():
    return make_response(jsonify({'message': 'Method Not Allowed'}), 405)
