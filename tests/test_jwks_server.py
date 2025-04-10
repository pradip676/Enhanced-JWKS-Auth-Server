import unittest
import sqlite3
import datetime

from server.jwks_server import auth_limiter
from server.jwks_server import app, create_users_table, create_auth_logs_table
from server.db_manager import (
    setup_database,
    generate_and_save_keys,
    fetch_valid_keys,
    get_rsa_key,
    store_rsa_key,
    AES_KEY,
    aes_encrypt,
    aes_decrypt
)

auth_limiter.requests.clear()

DB_FILE = "totally_not_my_privateKeys.db"


class TestProject3JWKS(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        setup_database()
        create_users_table()
        create_auth_logs_table()

    def setUp(self):
        self.client = app.test_client()
        self.clear_db()

    def tearDown(self):
        self.clear_db()

    def clear_db(self):
        with sqlite3.connect(DB_FILE) as conn:
            conn.execute("DELETE FROM keys")
            conn.execute("DELETE FROM users")
            conn.execute("DELETE FROM auth_logs")
            conn.commit()

    def test_aes_encryption_and_decryption(self):
        """Test AES encryption of private key."""
        plaintext = b"test-private-key-bytes"
        encrypted = aes_encrypt(plaintext, AES_KEY)
        decrypted = aes_decrypt(encrypted, AES_KEY)
        self.assertEqual(plaintext, decrypted)

    def test_register_endpoint_creates_user(self):
        """Test user registration via /register."""
        response = self.client.post(
            "/register",
            json={"username": "testuser", "email": "test@example.com"}
        )
        self.assertIn(response.status_code, (200, 201))
        self.assertIn("password", response.get_json())

        with sqlite3.connect(DB_FILE) as conn:
            row = conn.execute(
                "SELECT username FROM users WHERE username = ?",
                ("testuser",)
            ).fetchone()
            self.assertIsNotNone(row)

    def test_register_duplicate_user(self):
        """Test duplicate registration returns 409."""
        self.client.post(
            "/register",
            json={"username": "user", "email": "a@a.com"}
        )
        response = self.client.post(
            "/register",
            json={"username": "user", "email": "b@b.com"}
        )
        self.assertEqual(response.status_code, 409)

    def test_auth_endpoint_success(self):
        """Test /auth returns a JWT for valid user."""
        reg = self.client.post(
            "/register",
            json={"username": "authuser", "email": "auth@x.com"}
        )
        password = reg.get_json()["password"]
        generate_and_save_keys()

        response = self.client.post(
            "/auth",
            json={"username": "authuser", "password": password}
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("token", response.get_json())

    def test_auth_logging(self):
        """Test /auth logs the request to auth_logs."""
        reg = self.client.post(
            "/register",
            json={"username": "loguser", "email": "log@x.com"}
        )
        password = reg.get_json()["password"]
        generate_and_save_keys()

        self.client.post(
            "/auth",
            json={"username": "loguser", "password": password}
        )

        with sqlite3.connect(DB_FILE) as conn:
            log_count = conn.execute(
                "SELECT COUNT(*) FROM auth_logs"
            ).fetchone()[0]
            self.assertEqual(log_count, 1)

    def test_auth_rate_limit(self):
        """Test /auth rate limiter returns 429 after 10 requests/sec."""
        reg = self.client.post(
            "/register",
            json={"username": "rate", "email": "rate@x.com"}
        )
        password = reg.get_json()["password"]
        generate_and_save_keys()

        for _ in range(10):
            self.client.post(
                "/auth",
                json={"username": "rate", "password": password}
            )
        response = self.client.post(
            "/auth",
            json={"username": "rate", "password": password}
        )
        self.assertEqual(response.status_code, 429)

    def test_jwks_endpoint_returns_keys(self):
        """Test /.well-known/jwks.json returns public key(s)."""
        generate_and_save_keys()
        response = self.client.get("/.well-known/jwks.json")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIn("keys", data)
        self.assertGreater(len(data["keys"]), 0)

    def test_expired_key_fetching(self):
        """Test expired RSA key can be fetched correctly."""
        from cryptography.hazmat.primitives.asymmetric import rsa

        now = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
        expired_rsa_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        store_rsa_key(expired_rsa_key, now - 3600)

        kid, key = get_rsa_key(get_expired=True)
        self.assertIsNotNone(kid)
        self.assertIsNotNone(key)

    def test_auth_invalid_password(self):
        """Test /auth with wrong password returns 401."""
        self.client.post(
            "/register",
            json={"username": "user1", "email": "u@x.com"}
        )
        generate_and_save_keys()

        response = self.client.post(
            "/auth",
            json={"username": "user1", "password": "wrongpass"}
        )
        self.assertEqual(response.status_code, 401)

    def test_auth_unknown_user(self):
        """Test /auth with unknown username returns 401."""
        from server.jwks_server import auth_limiter
        auth_limiter.requests.clear()  # Reset rate limiter before test

        generate_and_save_keys()
        response = self.client.post(
            "/auth",
            json={"username": "nouser", "password": "x"}
        )
        self.assertEqual(response.status_code, 401)

    def test_fetch_valid_keys_directly(self):
        """Test fetch_valid_keys() returns unexpired keys."""
        generate_and_save_keys()
        keys = fetch_valid_keys()
        self.assertGreater(len(keys), 0)
        self.assertIsInstance(keys[0][0], int)  # kid
        self.assertIsInstance(keys[0][1], bytes)  # encrypted key blob


if __name__ == "__main__":
    unittest.main()
