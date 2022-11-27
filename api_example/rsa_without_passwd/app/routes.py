try:
    import datetime as dt
    from typing import Union
    from app import app, auth, gen_auth
    from flask import Response, make_response, jsonify
except ImportError as eImp:
    print(f"The following import ERROR occurred in {__file__}: {eImp}")

@gen_auth.enc_dec_jwt_config
def encode_private_key() -> dict[str, Union[str, bytes]]:
    file_private = "./private-key.pem"
    private_key = open(file_private).read().encode("ascii")

    encode_attributes = {
        "key": private_key,# In this case key should be your private key
        "algorithm": "RS256"
    }
    return encode_attributes

@auth.enc_dec_jwt_config
def decode_pub_key() -> dict[str, Union[str, bytes]]:
    file_public = "./public-key.pem"
    public_key = open(file_public).read().encode("ascii")

    decode_attributes = {
        "key": public_key,# In this case key should be your public key
        "algorithm": "RS256"
    }
    return decode_attributes

@gen_auth.personal_credentials_field
@auth.personal_credentials_field
def personal_credentials_field() -> tuple[str, str]:
    return "per_username", "per_password"

@gen_auth.verify_bauth_credentials
def get_basic_auth_credentials2(username: str, password: str) -> dict:
    # Use the username and password to authenticate the user in the way you want-
    # and return true if the user is authenticated
    if username == "admin2" and password == "passwd2":
        return True
    else:
        return False

@auth.get_user_roles
@gen_auth.get_user_roles
def my_roles(username: str) -> list[str]:
    # Use username to get roles from database
    print(f"username in roles: {username}")
    return ["admin", "user"]

@auth.get_jwt_claims_to_verify
def get_jwt_claims_to_verify() -> list[str]:
    # return ["exp", "iat", "nbf"]
    return ["exp", "iat"]

@gen_auth.jwt_claims
def jwt_claims() -> dict:
    claims = {
        "exp": dt.datetime.now(tz=dt.timezone.utc) + dt.timedelta(seconds=30),
        "iat": dt.datetime.now(tz=dt.timezone.utc)
    }
    return claims

@auth.verify_jwt_credentials
def creds(username_jwt: str, password_jwt: str) -> bool:
    my_dict = {
        "username_jwt": username_jwt,
        "password_jwt": password_jwt
    }
    return True
    # return False

# -------------Endpoints-------------
@app.route("/")
@auth.login_required(roles=["admin", "eder"])
def index() -> Response:
    return make_response("Todo bien", 200)

@app.route("/generate_token", methods=["POST"])
@gen_auth.generate_jwt(roles=["eder", "user"])
def gen_token(token) -> Response:
    response = {
        "status": "success",
        "token": token
    }
    return make_response(jsonify(response)), 200

@app.route("/temp")
def temp() -> Response:
    test = (("val1", "hola"), ("val2", "prueba2"))
    response = {
        "message": "solo prueba",
        "test_data": test
    }
    return make_response(jsonify(response))