import base64
import sqlite3
import time
import uuid

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from flask import Flask, jsonify, request

app = Flask(__name__)
DB_NAME = "totally_not_my_privateKeys.db"


def init_db():
    """Create the SQLite database and keys table."""

    with sqlite3.connect(DB_NAME) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS keys(
                kid INTEGER PRIMARY KEY AUTOINCREMENT,
                key BLOB NOT NULL,
                exp INTEGER NOT NULL
            )
        """)
        conn.commit()


def generate_key(expired=False):
    """Generate an RSA key pair with a unique ID and expiration."""

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    public_key = private_key.public_key()
    kid = str(uuid.uuid4())

    if expired:
        expiry = int(time.time()) - 3600
    else:
        expiry = int(time.time()) + 3600

    return {
        "private_key": private_key,
        "public_key": public_key,
        "kid": kid,
        "expiry": expiry,
    }


def save_key(expired=False):
    """Generate and save an RSA private key in SQLite."""

    key_data = generate_key(expired=expired)

    private_key = key_data["private_key"]

    # Serialize the private key into PEM bytes.
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    # Use parameters to prevent SQL injection.
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.execute(
            "INSERT INTO keys (key, exp) VALUES (?, ?)",
            (pem, key_data["expiry"]),
        )
        conn.commit()

        return cursor.lastrowid

def get_key(expired=False):
    """Retrieve an RSA private key from SQLite."""

    current_time = int(time.time())

    with sqlite3.connect(DB_NAME) as conn:
        if expired:
            cursor = conn.execute(
                """
                SELECT kid, key, exp
                FROM keys
                WHERE exp <= ?
                ORDER BY exp DESC
                LIMIT 1
                """,
                (current_time,),
            )
        else:
            cursor = conn.execute(
                """
                SELECT kid, key, exp
                FROM keys
                WHERE exp > ?
                ORDER BY exp DESC
                LIMIT 1
                """,
                (current_time,),
            )

        row = cursor.fetchone()

    if row is None:
        return None

    kid, pem, expiry = row

    private_key = serialization.load_pem_private_key(
        pem,
        password=None,
    )

    return {
        "kid": str(kid),
        "private_key": private_key,
        "public_key": private_key.public_key(),
        "expiry": expiry,
    }

def int_to_base64(value):
    """Convert an integer to Base64URL encoding."""

    length = (value.bit_length() + 7) // 8
    value_bytes = value.to_bytes(length, byteorder="big")

    return (
        base64.urlsafe_b64encode(value_bytes)
        .rstrip(b"=")
        .decode("utf-8")
    )


def key_to_jwk(key):
    """Convert an RSA public key to JWK format."""

    public_numbers = key["public_key"].public_numbers()

    return {
        "kty": "RSA",
        "kid": key["kid"],
        "use": "sig",
        "alg": "RS256",
        "n": int_to_base64(public_numbers.n),
        "e": int_to_base64(public_numbers.e),
    }

@app.route("/.well-known/jwks.json", methods=["GET"])
def jwks():
    """Return all non-expired public keys from SQLite."""

    current_time = int(time.time())
    keys = []

    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.execute(
            """
            SELECT kid, key, exp
            FROM keys
            WHERE exp > ?
            """,
            (current_time,),
        )
        rows = cursor.fetchall()

    for kid, pem, expiry in rows:
        private_key = serialization.load_pem_private_key(
            pem,
            password=None,
        )

        key_data = {
            "kid": str(kid),
            "private_key": private_key,
            "public_key": private_key.public_key(),
            "expiry": expiry,
        }

        keys.append(key_to_jwk(key_data))

    return jsonify({"keys": keys}), 200


@app.route("/auth", methods=["POST"])
def auth():
    """Issue a JWT using a private key from SQLite."""

    use_expired = "expired" in request.args
    selected_key = get_key(expired=use_expired)

    if selected_key is None:
        return jsonify({"error": "No matching key found"}), 500

    current_time = int(time.time())

    expiration = (
        current_time - 3600
        if use_expired
        else min(current_time + 3600, selected_key["expiry"])
    )

    payload = {
        "sub": "fake-user",
        "iat": current_time,
        "exp": expiration,
    }

    token = jwt.encode(
        payload,
        selected_key["private_key"],
        algorithm="RS256",
        headers={"kid": selected_key["kid"]},
    )

    return token, 200, {"Content-Type": "application/jwt"}



if __name__ == "__main__":
    init_db()
    save_key(expired=True)
    save_key(expired=False)
    app.run(port=8080)