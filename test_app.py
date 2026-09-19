import time

import jwt

from app import app, expired_key, valid_key


def test_jwks_endpoint():
    client = app.test_client()

    response = client.get("/.well-known/jwks.json")

    assert response.status_code == 200

    data = response.get_json()

    assert "keys" in data
    assert len(data["keys"]) == 1

    key = data["keys"][0]

    assert key["kid"] == valid_key["kid"]
    assert key["kty"] == "RSA"
    assert key["alg"] == "RS256"
    assert key["use"] == "sig"


def test_expired_key_not_in_jwks():
    client = app.test_client()

    response = client.get("/.well-known/jwks.json")
    data = response.get_json()

    kids = [key["kid"] for key in data["keys"]]

    assert expired_key["kid"] not in kids


def test_auth_returns_valid_jwt():
    client = app.test_client()

    response = client.post("/auth")

    assert response.status_code == 200

    token = response.get_data(as_text=True)

    header = jwt.get_unverified_header(token)

    assert header["kid"] == valid_key["kid"]
    assert header["alg"] == "RS256"

    payload = jwt.decode(
        token,
        valid_key["public_key"],
        algorithms=["RS256"],
    )

    assert payload["sub"] == "fake-user"
    assert payload["exp"] > int(time.time())


def test_expired_auth():
    client = app.test_client()

    response = client.post("/auth?expired=true")

    assert response.status_code == 200

    token = response.get_data(as_text=True)

    header = jwt.get_unverified_header(token)

    assert header["kid"] == expired_key["kid"]

    payload = jwt.decode(
        token,
        expired_key["public_key"],
        algorithms=["RS256"],
        options={"verify_exp": False},
    )

    assert payload["exp"] < int(time.time())


def test_auth_get_not_allowed():
    client = app.test_client()

    response = client.get("/auth")

    assert response.status_code == 405


def test_jwks_post_not_allowed():
    client = app.test_client()

    response = client.post("/.well-known/jwks.json")

    assert response.status_code == 405