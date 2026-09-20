try:
    import datetime as dt
    from app import app, auth, gen_auth
    from flask import Response, make_response, jsonify
except ImportError as eImp:
    print(f"The following import ERROR occurred in {__file__}: {eImp}")


@gen_auth.enc_dec_jwt_config
@auth.enc_dec_jwt_config
def enc_dec_creds() -> dict:
    return {
        "key": "secret",
        "algorithm": "HS256",
        "leeway": 10,
    }


@gen_auth.verify_bauth_credentials
def check_credentials(username: str, password: str) -> bool:
    # Validate against your user store; return True when valid.
    return username == "admin2" and password == "passwd2"


@auth.get_user_roles
@gen_auth.get_user_roles
def user_roles(subject: str) -> list:
    # Look up roles for the subject (username) from your store.
    return ["admin", "user"]


@auth.verify_jwt_credentials
def user_is_valid(subject: str) -> bool:
    # The signature already authenticates the token; here you only confirm the
    # user still exists / is active. No password is involved.
    return subject == "admin2"


@auth.get_jwt_claims_to_verify
def required_claims() -> list:
    return ["exp", "iat", "sub"]


@gen_auth.jwt_claims
def extra_claims() -> dict:
    # Evaluated on every generation, so exp is always fresh.
    now = dt.datetime.now(tz=dt.timezone.utc)
    return {"exp": now + dt.timedelta(minutes=15), "iat": now}


# ------------- Endpoints -------------
@app.route("/generate_token", methods=["POST"])
@gen_auth.generate_jwt(roles=["user"], with_refresh=True)
def gen_token(access_token: str, refresh_token: str) -> Response:
    return make_response(
        jsonify(access_token=access_token, refresh_token=refresh_token), 200
    )


@app.route("/refresh", methods=["POST"])
@auth.refresh_jwt
def refresh(subject: str) -> Response:
    return make_response(jsonify(access_token=gen_auth.create_access_token(subject)), 200)


@app.route("/")
@auth.login_required(roles=["admin", "user"])
def index() -> Response:
    return make_response(jsonify(message="authorized"), 200)
