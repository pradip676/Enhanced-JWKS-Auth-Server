import sqlite3
import datetime
import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


DB_FILE = "totally_not_my_privateKeys.db"

# 32-byte AES key derived from environment or fallback
raw_key = os.environ.get("NOT_MY_KEY")
if not raw_key:
    raise EnvironmentError("Environment variable 'NOT_MY_KEY' is not set.")
    
if len(raw_key) < 32:
    raw_key = raw_key.ljust(32, "_")
elif len(raw_key) > 32:
    raw_key = raw_key[:32]
AES_KEY = raw_key.encode("utf-8")


def setup_database():
    with sqlite3.connect(DB_FILE) as connection:
        connection.execute(
            '''
            CREATE TABLE IF NOT EXISTS keys (
                kid INTEGER PRIMARY KEY AUTOINCREMENT,
                key BLOB NOT NULL,
                exp INTEGER NOT NULL
            )
            '''
        )


def aes_encrypt(plaintext: bytes, key: bytes) -> bytes:
    iv = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(iv, plaintext, None)
    return iv + ciphertext


def aes_decrypt(data: bytes, key: bytes) -> bytes:
    iv = data[:12]
    ciphertext = data[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(iv, ciphertext, None)


def store_rsa_key(rsa_obj, expiry):
    pem_data = rsa_obj.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    encrypted_blob = aes_encrypt(pem_data, AES_KEY)
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute(
            'INSERT INTO keys (key, exp) VALUES (?, ?)',
            (encrypted_blob, expiry)
        )


def get_rsa_key(get_expired=False):
    now_ts = int(datetime.datetime.now(datetime.timezone.utc).timestamp())

    query = '''
        SELECT kid, key FROM keys
        WHERE exp {} ?
        ORDER BY exp {} LIMIT 1
    '''.format('<' if get_expired else '>', 'DESC' if get_expired else 'ASC')

    with sqlite3.connect(DB_FILE) as connection:
        cursor = connection.execute(query, (now_ts,))
        record = cursor.fetchone()

    if record:
        kid = record[0]
        decrypted = aes_decrypt(record[1], AES_KEY)
        rsa_key = serialization.load_pem_private_key(decrypted, password=None)
        return kid, rsa_key
    return None, None


def generate_and_save_keys():
    now_ts = int(datetime.datetime.now(datetime.timezone.utc).timestamp())

    valid_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    expired_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    store_rsa_key(valid_key, now_ts + 3600)
    store_rsa_key(expired_key, now_ts - 3600)


def fetch_valid_keys():
    now_ts = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
    with sqlite3.connect(DB_FILE) as connection:
        cursor = connection.execute(
            'SELECT kid, key FROM keys WHERE exp > ?',
            (now_ts,)
        )
        return cursor.fetchall()
