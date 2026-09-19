# CSCE 3550 Project 1 - JWKS Server

**Student:** Rayshma Choudary Ravi

## Description

This project implements a basic JWKS server using Python and Flask.

The server generates RSA key pairs with unique Key IDs (kid) and
expiration timestamps. It serves valid public keys through a JWKS
endpoint and issues signed JSON Web Tokens (JWTs).

## Endpoints

### GET /.well-known/jwks.json

Returns valid, non-expired RSA public keys in JWKS format.

### POST /auth

Returns a valid JWT signed using the valid RSA private key.

### POST /auth?expired=true

Returns an intentionally expired JWT signed using the expired RSA
private key.

## Installation

Install the required dependencies:

pip install -r requirements.txt

## Running the Server

Run:

python app.py

The server runs on port 8080.

## Testing

Run the test suite:

pytest

## Test Coverage

Run:

pytest --cov=app --cov-report=term-missing

The project includes automated tests for the JWKS endpoint, valid JWTs,
expired JWTs, expired-key filtering, and HTTP method handling.

## Author

Rayshma Choudary Ravi