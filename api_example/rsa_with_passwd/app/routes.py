try:
    import datetime as dt
    from app import app, auth, gen_auth
    from flask import Response, make_response, jsonify
except ImportError as eImp:
    print(f"The following import ERROR occurred in {__file__}: {eImp}")

# Read the keys once at import instead of on every request.
with open("./private-key.pem", "rb") as _priv:
    _PRIVATE_KEY = _priv.read()
with open("./public-key.pem", "rb") as _pub:
    _PUBLIC_KEY = _pub.read()


@gen_auth.enc_dec_jwt_config
def signing_config() -> dict:
    # gen_auth was created with rsa_encrypt=True, so the private key is decrypted
    # with this passphrase before signing.
    return {"key": _PRIVATE_KEY, "algorithm": "RS256", "passphrase": b"your password"}


@auth.enc_dec_jwt_config
def verification_config() -> dict:
    return {"key": _PUBLIC_KEY, "algorithm": "RS256"}


@gen_auth.verify_bauth_credentials
def check_credentials(username: str, password: str) -> bool:
    return username == "admin2" and password == "passwd2"


@auth.get_user_roles
@gen_auth.get_user_roles
def user_roles(subject: str) -> list:
    return ["admin", "user"]


@auth.verify_jwt_credentials
def user_is_valid(subject: str) -> bool:
    return subject == "admin2"


@gen_auth.jwt_claims
def extra_claims() -> dict:
    now = dt.datetime.now(tz=dt.timezone.utc)
    return {"exp": now + dt.timedelta(minutes=15), "iat": now}


# ------------- Endpoints -------------
@app.route("/generate_token", methods=["POST"])
@gen_auth.generate_jwt(roles=["user"])
def gen_token(access_token: str) -> Response:
    return make_response(jsonify(access_token=access_token), 200)


@app.route("/")
@auth.login_required(roles=["admin", "user"])
def index() -> Response:
    return make_response(jsonify(message="authorized"), 200)
