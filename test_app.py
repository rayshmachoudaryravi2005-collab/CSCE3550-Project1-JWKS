import sqlite3
import time

import jwt
import pytest

import app as jwks_server


@pytest.fixture
def db_client(tmp_path, monkeypatch):
    """Create an isolated SQLite database for each test."""
    db_path = tmp_path / "test_keys.db"
    monkeypatch.setattr(jwks_server, "DB_NAME", str(db_path))

    jwks_server.init_db()
    expired_kid = jwks_server.save_key(expired=True)
    valid_kid = jwks_server.save_key(expired=False)

    client = jwks_server.app.test_client()
    return client, expired_kid, valid_kid


def test_database_created(db_client):
    """Verify SQLite database and table exist."""
    with sqlite3.connect(jwks_server.DB_NAME) as conn:
        rows = conn.execute(
            "SELECT kid, key, exp FROM keys"
        ).fetchall()

    assert len(rows) == 2
    assert all(isinstance(row[1], bytes) for row in rows)


def test_jwks_endpoint(db_client):
    client, expired_kid, valid_kid = db_client

    response = client.get("/.well-known/jwks.json")

    assert response.status_code == 200

    data = response.get_json()
    assert "keys" in data
    assert len(data["keys"]) == 1

    key = data["keys"][0]
    assert key["kid"] == str(valid_kid)
    assert key["kid"] != str(expired_kid)
    assert key["kty"] == "RSA"
    assert key["alg"] == "RS256"
    assert key["use"] == "sig"
    assert key["e"] == "AQAB"
    assert key["n"]


def test_auth_returns_valid_jwt(db_client):
    client, _, valid_kid = db_client

    response = client.post("/auth")
    assert response.status_code == 200

    token = response.get_data(as_text=True)
    header = jwt.get_unverified_header(token)

    assert header["kid"] == str(valid_kid)
    assert header["alg"] == "RS256"

    selected_key = jwks_server.get_key(expired=False)

    payload = jwt.decode(
        token,
        selected_key["public_key"],
        algorithms=["RS256"],
    )

    assert payload["sub"] == "fake-user"
    assert payload["exp"] > int(time.time())


def test_expired_auth(db_client):
    client, expired_kid, _ = db_client

    response = client.post("/auth?expired=true")
    assert response.status_code == 200

    token = response.get_data(as_text=True)
    header = jwt.get_unverified_header(token)

    assert header["kid"] == str(expired_kid)

    selected_key = jwks_server.get_key(expired=True)

    payload = jwt.decode(
        token,
        selected_key["public_key"],
        algorithms=["RS256"],
        options={"verify_exp": False},
    )

    assert payload["exp"] < int(time.time())


def test_get_key_no_match(db_client):
    """Check behavior when no matching key exists."""
    with sqlite3.connect(jwks_server.DB_NAME) as conn:
        conn.execute("DELETE FROM keys")
        conn.commit()

    assert jwks_server.get_key(expired=False) is None
    assert jwks_server.get_key(expired=True) is None


def test_auth_without_keys(db_client):
    """Verify an error is returned if no signing key exists."""
    client, _, _ = db_client

    with sqlite3.connect(jwks_server.DB_NAME) as conn:
        conn.execute("DELETE FROM keys")
        conn.commit()

    response = client.post("/auth")
    assert response.status_code == 500
    assert "error" in response.get_json()

    response = client.post("/auth?expired=true")
    assert response.status_code == 500


def test_jwks_without_keys(db_client):
    client, _, _ = db_client

    with sqlite3.connect(jwks_server.DB_NAME) as conn:
        conn.execute("DELETE FROM keys")
        conn.commit()

    response = client.get("/.well-known/jwks.json")
    assert response.status_code == 200
    assert response.get_json() == {"keys": []}


def test_auth_get_not_allowed(db_client):
    client, _, _ = db_client
    response = client.get("/auth")
    assert response.status_code == 405


def test_jwks_post_not_allowed(db_client):
    client, _, _ = db_client
    response = client.post("/.well-known/jwks.json")
    assert response.status_code == 405


def test_multiple_valid_keys(db_client):
    client, _, _ = db_client

    second_kid = jwks_server.save_key(expired=False)

    response = client.get("/.well-known/jwks.json")
    keys = response.get_json()["keys"]

    assert len(keys) == 2
    assert str(second_kid) in [key["kid"] for key in keys]


def test_basic_auth_and_json_payload(db_client):
    """The assignment's mock authentication accepts both formats."""
    client, _, _ = db_client

    basic_response = client.post(
        "/auth",
        headers={"Authorization": "Basic dXNlcjpwYXNz"},
    )

    json_response = client.post(
        "/auth",
        json={
            "username": "userABC",
            "password": "password123",
        },
    )

    assert basic_response.status_code == 200
    assert json_response.status_code == 200