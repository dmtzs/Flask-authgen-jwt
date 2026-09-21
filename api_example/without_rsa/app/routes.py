"""Example Flask routes wired to flask_authgen_jwt (HS256, no RSA)."""
try:
    import datetime as dt
    from app import app, auth, gen_auth  # pylint: disable=import-error
    from flask import Response, make_response, jsonify
except ImportError as eImp:
    print(f"The following import ERROR occurred in {__file__}: {eImp}")


@gen_auth.enc_dec_jwt_config
@auth.enc_dec_jwt_config
def enc_dec_creds() -> dict:
    """Return the shared HS256 signing/verification config."""
    return {
        "key": "secret",
        "algorithm": "HS256",
        "leeway": 10,
    }


@gen_auth.verify_bauth_credentials
def check_credentials(username: str, password: str) -> bool:
    """Validate against your user store; return True when valid."""
    return username == "admin2" and password == "passwd2"


@auth.get_user_roles
@gen_auth.get_user_roles
def user_roles(_subject: str) -> list:
    """Look up roles for the subject (username) from your store."""
    return ["admin", "user"]


@auth.verify_jwt_credentials
def user_is_valid(subject: str) -> bool:
    """Confirm the subject still exists/is active (no password involved)."""
    return subject == "admin2"


@auth.get_jwt_claims_to_verify
def required_claims() -> list:
    """Claims that must be present and validated on every incoming token."""
    return ["exp", "iat", "sub"]


@gen_auth.jwt_claims
def extra_claims() -> dict:
    """Extra claims added on every token generation, so exp is always fresh."""
    now = dt.datetime.now(tz=dt.timezone.utc)
    return {"exp": now + dt.timedelta(minutes=15), "iat": now}


# ------------- Endpoints -------------
@app.route("/generate_token", methods=["POST"])
@gen_auth.generate_jwt(roles=["user"], with_refresh=True)
def gen_token(access_token: str, refresh_token: str) -> Response:
    """Issue an access token and a refresh token for valid credentials."""
    return make_response(
        jsonify(access_token=access_token, refresh_token=refresh_token), 200
    )


@app.route("/refresh", methods=["POST"])
@auth.refresh_jwt
def refresh(subject: str) -> Response:
    """Issue a fresh access token from a valid refresh token."""
    return make_response(jsonify(access_token=gen_auth.create_access_token(subject)), 200)


@app.route("/")
@auth.login_required(roles=["admin", "user"])
def index() -> Response:
    """Protected route reachable only with a valid access token."""
    return make_response(jsonify(message="authorized"), 200)
