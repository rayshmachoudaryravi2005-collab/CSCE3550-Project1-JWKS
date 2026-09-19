import base64
import time
import uuid

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from flask import Flask, jsonify, request

app = Flask(__name__)


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


valid_key = generate_key()
expired_key = generate_key(expired=True)


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
    """Return only non-expired public keys."""

    keys = []

    if valid_key["expiry"] > int(time.time()):
        keys.append(key_to_jwk(valid_key))

    return jsonify({"keys": keys}), 200


@app.route("/auth", methods=["POST"])
def auth():
    """Issue a valid or intentionally expired JWT."""

    use_expired = "expired" in request.args

    if use_expired:
        selected_key = expired_key
        expiration = int(time.time()) - 3600
    else:
        selected_key = valid_key
        expiration = int(time.time()) + 3600

    payload = {
        "sub": "fake-user",
        "iat": int(time.time()),
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
    app.run(port=8080)