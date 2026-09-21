"""Example Flask routes wired to flask_authgen_jwt (RSA, private key without passphrase)."""
try:
    import datetime as dt
    from typing import Union
    from app import app, auth, gen_auth  # pylint: disable=import-error
    from flask import Response, make_response, jsonify
except ImportError as eImp:
    print(f"The following import ERROR occurred in {__file__}: {eImp}")

@gen_auth.enc_dec_jwt_config
def encode_private_key() -> dict[str, Union[str, bytes]]:
    """Load and return the RSA private key used to sign tokens."""
    file_private = "./private-key.pem"
    with open(file_private, encoding="ascii") as handle:
        private_key = handle.read().encode("ascii")

    encode_attributes = {
        "key": private_key,  # In this case key should be your private key
        "algorithm": "RS256"
    }
    return encode_attributes

@auth.enc_dec_jwt_config
def decode_pub_key() -> dict[str, Union[str, bytes]]:
    """Load and return the RSA public key used to verify tokens."""
    file_public = "./public-key.pem"
    with open(file_public, encoding="ascii") as handle:
        public_key = handle.read().encode("ascii")

    decode_attributes = {
        "key": public_key,  # In this case key should be your public key
        "algorithm": "RS256"
    }
    return decode_attributes

@gen_auth.personal_credentials_field
@auth.personal_credentials_field
def personal_credentials_field() -> tuple[str, str]:
    """Customize the subject claim name used in the token payload."""
    return "per_username", "per_password"

@gen_auth.verify_bauth_credentials
def get_basic_auth_credentials2(username: str, password: str) -> dict:
    """Use the username and password to authenticate the user in the way you want."""
    return username == "admin2" and password == "passwd2"

@auth.get_user_roles
@gen_auth.get_user_roles
def my_roles(username: str) -> list[str]:
    """Use username to get roles from database."""
    print(f"username in roles: {username}")
    return ["admin", "user"]

@auth.get_jwt_claims_to_verify
def get_jwt_claims_to_verify() -> list[str]:
    """Claims that must be present and validated on every incoming token."""
    # return ["exp", "iat", "nbf"]
    return ["exp", "iat"]

@gen_auth.jwt_claims
def jwt_claims() -> dict:
    """Extra claims added on every token generation."""
    claims = {
        "exp": dt.datetime.now(tz=dt.timezone.utc) + dt.timedelta(seconds=30),
        "iat": dt.datetime.now(tz=dt.timezone.utc)
    }
    return claims

@auth.verify_jwt_credentials
def creds(_username_jwt: str, _password_jwt: str) -> bool:
    """Confirm the subject still exists/is active for this example."""
    return True
    # return False

# -------------Endpoints-------------
@app.route("/")
@auth.login_required(roles=["admin", "eder"])
def index() -> Response:
    """Protected route reachable only with a valid access token."""
    return make_response("Todo bien", 200)

@app.route("/generate_token", methods=["POST"])
@gen_auth.generate_jwt(roles=["eder", "user"])
def gen_token(token) -> Response:
    """Issue an access token for valid credentials."""
    response = {
        "status": "success",
        "token": token
    }
    return make_response(jsonify(response)), 200

@app.route("/temp")
def temp() -> Response:
    """Sample route returning a fixed payload, for manual testing."""
    test = (("val1", "hola"), ("val2", "prueba2"))
    response = {
        "message": "solo prueba",
        "test_data": test
    }
    return make_response(jsonify(response))
