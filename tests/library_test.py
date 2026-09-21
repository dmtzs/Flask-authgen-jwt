"""Unit tests for the flask_authgen_jwt library."""
import os
import sys
import base64
import unittest

is_github_action = os.getenv("GITHUB_ACTIONS") == "true"
sys.path.append("src" if is_github_action else "../src")

import jwt as pyjwt
from flask import Flask, jsonify, make_response
from flask_authgen_jwt import DecJwt, GenJwt, get_current_subject

SECRET = "unit-test-secret-key-at-least-32-bytes-long"


def _basic(username: str, password: str) -> str:
    return "Basic " + base64.b64encode(f"{username}:{password}".encode()).decode()


def build_app() -> Flask:
    """Build a minimal Flask app wired with GenJwt/DecJwt for the tests."""
    app = Flask(__name__)
    gen = GenJwt(access_ttl_seconds=60)
    dec = DecJwt()

    @gen.enc_dec_jwt_config
    @dec.enc_dec_jwt_config
    def cfg() -> dict:
        return {"key": SECRET, "algorithm": "HS256", "leeway": 5}

    @gen.verify_bauth_credentials
    def check(username: str, password: str) -> bool:
        return username == "test" and password == "test"

    @gen.get_user_roles
    @dec.get_user_roles
    def roles(_subject: str) -> list:
        return ["user"]

    @dec.verify_jwt_credentials
    def user_valid(subject: str) -> bool:
        return subject == "test"

    @app.post("/token")
    @gen.generate_jwt(roles=["user"], with_refresh=True)
    def token(access: str, refresh: str):
        return make_response(jsonify(access_token=access, refresh_token=refresh), 200)

    @app.post("/refresh")
    @dec.refresh_jwt
    def refresh(subject: str):
        return make_response(jsonify(access_token=gen.create_access_token(subject)), 200)

    @app.get("/protected")
    @dec.login_required(roles=["user"])
    def protected():
        return make_response(jsonify(subject=get_current_subject()), 200)

    return app


class TestFlaskAuthgenJwt(unittest.TestCase):
    """End-to-end tests for token generation, refresh and protected routes."""

    def setUp(self) -> None:
        """Create a fresh Flask test client for every test."""
        self.client = build_app().test_client()

    def test_token_never_contains_password(self):
        """The signed access token must never carry the plaintext password."""
        res = self.client.post("/token", headers={"Authorization": _basic("test", "test")})
        self.assertEqual(res.status_code, 200)
        access = res.get_json()["access_token"]
        payload = pyjwt.decode(access, SECRET, algorithms=["HS256"])
        self.assertNotIn("password", payload)
        self.assertEqual(payload["sub"], "test")
        self.assertEqual(payload["type"], "access")
        self.assertIn("jti", payload)

    def test_bad_credentials_are_rejected(self):
        """Wrong basic-auth credentials must be rejected with 401."""
        res = self.client.post("/token", headers={"Authorization": _basic("test", "wrong")})
        self.assertEqual(res.status_code, 401)

    def test_protected_requires_a_token(self):
        """A protected route without a bearer token must return 401."""
        self.assertEqual(self.client.get("/protected").status_code, 401)

    def test_full_access_and_refresh_flow(self):
        """An issued access token must be usable on a protected route."""
        res = self.client.post("/token", headers={"Authorization": _basic("test", "test")})
        access = res.get_json()["access_token"]
        refresh = res.get_json()["refresh_token"]

        ok = self.client.get("/protected", headers={"Authorization": f"Bearer {access}"})
        self.assertEqual(ok.status_code, 200)
        self.assertEqual(ok.get_json()["subject"], "test")

        # A refresh token must not grant access to protected resources.
        denied = self.client.get("/protected", headers={"Authorization": f"Bearer {refresh}"})
        self.assertEqual(denied.status_code, 401)

        # The refresh endpoint issues a new access token.
        renewed = self.client.post("/refresh", headers={"Authorization": f"Bearer {refresh}"})
        self.assertEqual(renewed.status_code, 200)
        self.assertIn("access_token", renewed.get_json())


if __name__ == "__main__":
    unittest.main()
