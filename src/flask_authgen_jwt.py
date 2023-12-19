"""
flask_authgen_jwt
==================
This module provides creation of new jwt also using basic auth to get the jwt and decode of the jwt.
:copyright: (C) 2022 by Diego Martinez Sanchez and Guillermo Ortega Romo.
:license:   MIT, see LICENSE for more details.
"""

try:
    import jwt
    from functools import wraps
    from base64 import b64decode
    from datetime import datetime
    from http import HTTPStatus
    from typing import Callable, Optional, Union
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend
    from flask import request, current_app, abort, make_response, jsonify
except ImportError as eImp:
    print(f"The following import ERROR occurred in {__file__}: {eImp}")

class Core():
    """
    Class to set the core of the library, this class is inherited by the other classes of the library.

    Args:
    - None

    Returns:
    - None
    """
    basic_auth_callback: Callable[[str, str], bool] = None
    enc_dec_jwt_callback: dict[str, Union[bytes, str]] = None
    get_user_roles_callback: list[str] = None
    personal_credentials: tuple[str, str] = None

    def enc_dec_jwt_config(self, func: Callable[[None], dict[str, Union[bytes, str]]]) -> Callable[[None], dict[str, Union[bytes, str]]]:
        """Decorator to verify the JWT token

        Args:
        - func: function to be decorated
        
        Returns:
        - Callable: the function to wrap should return a dictionary with the following keys:
            - key: key to decode the JWT
            - algorithm: algorithm to decode the JWT
        
        ### Example
        ```python
        @dec_jwt.enc_dec_jwt_config
        def enc_dec_creds() -> dict[str, str]:
            enc_dec_attributes = {
                "key": "secret",
                "algorithm": "HS256",
            }
            return enc_dec_attributes
        ```
        """
        self.enc_dec_jwt_callback = func()
        return func

    def personal_credentials_field(self, func: Callable[[None], tuple[str, str]]) -> Callable[[None], tuple[str, str]]:
        """
        Decorator to set the personal credentials, if youu dont want to use username and password inside the token
        then with this you can return a tuple in which the first element is the username and the second is the password
        but as you want to name that respective fields so the library will validate using the fields you set

        Args:
        - func: function to be decorated

        Returns:
        - Callable: the function to wrap should return a tuple with the username and password fields

        ### Example
        ```python
        @dec_jwt.personal_credentials_field
        def get_personal_credentials():
            return "my_username_personal_name_field", "my_password_personal_name_field"
        ```
        """
        self.personal_credentials = func()
        return func

    def verify_dict_config(self, config: str) -> None:
        """
        Method that veryfies the JWT configuration generator

        Args:
        - config: string to identify which configuration to verify
        """
        if config == "jwt":
            claims = ["key", "algorithm"]
            for claim in claims:
                if claim not in self.enc_dec_jwt_callback:
                    self.gen_abort_error(f"The claim {claim} is not in the dictionary", HTTPStatus.BAD_REQUEST.value)
        elif config == "rsa_pass":
            if "passphrase" not in self.enc_dec_jwt_callback:
                self.gen_abort_error("The claim passphrase is not in the dictionary", HTTPStatus.BAD_REQUEST.value)

    def verify_user_roles(self, roles: list, user: str) -> None:
        """
        Method to verify the user roles if are correct

        Args:
        - roles: list of roles to verify against the user roles callback
        """
        if roles is not None:
            if self.get_user_roles_callback is None:
                self.gen_abort_error("get_user_roles decorator and function is not defined is not defined", 500)
            else:
                user_roles = self.ensure_sync(self.get_user_roles_callback)(user)
                # if not set(roles).issubset(set(user_roles)):
                role_flag = False
                for role in user_roles:
                    if role in roles:
                        role_flag = True
                        break
                if not role_flag:
                    self.gen_abort_error("User does not have the required roles", 403)

    def get_user_roles(self, func: Callable[[str], list[str]]) -> Callable[[str], list[str]]:
        """
        Decorator to get the user roles by the user that was received from the JWT or basic auth.
        To the function you will decorate with this decorator you will have available the user variable.

        Args:
        - func: function to be decorated

        Returns:
        - Callable: the function to wrap that returns a list of the user roles
        
        ### Example
        ```python
        @dec_jwt.get_user_roles
        def my_roles(username: str) -> list[str]:
            # Use username to get roles from database
            print(f"username in roles: {username}")
            return ["admin", "user"]
        ```
        """
        self.get_user_roles_callback = func
        return func

    def gen_abort_error(self, error: str, status_code: int) -> None:
        """
        Method to generate the abort error with the error message and status code

        Args:
        - error: error message in string format
        - status_code: status code in int format

        Returns:
        - None
        """
        abort(make_response(jsonify({"error": error}), status_code))

    def ensure_sync(self, func: Callable) -> Callable:
        """
        Decorator to ensure the function is synchronous.

        Args:
        - func: function to be decorated

        Returns:
        - Callable: the function to wrap
        """
        try:
            return current_app.ensure_sync(func)
        except AttributeError:
            return func

class GenJwt(Core):
    """
    Class to generate the JWT token, the user should set the key and algorithm to encode the JWT-
    and also the claims that will be added to the JWT payload.

    Args:
    - rsa_encrypt: boolean to specify if the key is encrypted or not
    - json_body_token: boolean to specify if the token will be sent in the body of the request or not

    Returns:
    - None
    """
    def __init__(self, rsa_encrypt: bool = False, json_body_token: bool = False) -> None:
        """
        Constructor of the class

        Args:
        - rsa_encrypt: boolean to specify if the key is encrypted or not
        - json_body_token: boolean to specify if the token will be sent in the body of the request or not

        Returns:
        - None
        """
        self.jwt_fields_attr: dict[str, datetime] = None
        self.rsa_encrypt: bool = rsa_encrypt
        self.json_body_token: bool = json_body_token

    def __create_jwt_payload(self, bauth_credentials: dict[str, str]) -> dict[str, Union[str, datetime]]:
        """
        Method to create the JWT payload but still not encoded

        Args:
        - bauth_credentials: credentials of the user

        Returns:
        - dict: dictionary with the JWT payload
        """
        if not self.jwt_fields_attr:
            self.gen_abort_error("jwt_claims decorator and function is not defined", 500)
        if self.json_body_token:
            if not request.is_json:
                self.gen_abort_error("Missing JSON in request or not JSON format sent to endpoint", HTTPStatus.BAD_REQUEST.value)
            else:
                bauth_credentials = request.get_json()
        if self.personal_credentials is not None:
            bauth_credentials[self.personal_credentials[0]] = bauth_credentials.pop("username")
            bauth_credentials[self.personal_credentials[1]] = bauth_credentials.pop("password")
        payload = bauth_credentials
        payload.update(self.jwt_fields_attr)

        return payload

    def __dec_set_basic_auth(self) -> Optional[bool]:
        """
        Method to decode and verify the basic auth credentials in the expected format.

        Args:
        - None

        Returns:
        - bool: True if the credentials are correct, False if not
        """
        auth_header = request.headers.get("Authorization")
        if auth_header is None:
            self.gen_abort_error("Authorization header is missing", HTTPStatus.BAD_REQUEST.value)
        auth_header = auth_header.split(" ")
        if auth_header[0] != "Basic":
            self.gen_abort_error("Authorization header must be Basic", HTTPStatus.BAD_REQUEST.value)
        credentials = auth_header[1]
        credentials = b64decode(credentials).decode("utf-8")
        credentials = credentials.split(":")
        if len(credentials) != 2:
            self.gen_abort_error("Authorization header must be Basic with user and password only", HTTPStatus.BAD_REQUEST.value)
        username = credentials[0]
        password = credentials[1]
        bauth_credentials = {
            "username": username,
            "password": password
        }
        if self.basic_auth_callback:
            return self.ensure_sync(self.basic_auth_callback)(
                username, password), bauth_credentials
        else:
            self.gen_abort_error("basic_auth decorator and function is not defined", 500)

    def __encode_jwt(self, payload: dict) -> Optional[str]:
        """
        Method to encode the JWT token using the key and algorithm specified in the enc_dec_jwt_config decorator
        that returns the dictionary with the configuration.

        Args:
        - payload: dictionary with the JWT payload

        Returns:
        - str: encoded token or None if an error occurred
        :return: the encoded token or None if an error occurred
        """
        self.verify_dict_config("jwt")
        key = self.enc_dec_jwt_callback["key"]
        algorithm = self.enc_dec_jwt_callback["algorithm"]
        try:
            if algorithm == "HS256":
                encoded_token = jwt.encode(payload, key, algorithm=algorithm)
            elif algorithm == "RS256":
                if self.rsa_encrypt:
                    self.verify_dict_config("rsa_pass")
                    passphrase = self.enc_dec_jwt_callback["passphrase"]
                    private_key = serialization.load_pem_private_key(
                            key, password=passphrase, backend=default_backend())
                    encoded_token = jwt.encode(payload, private_key, algorithm=algorithm)
                elif not self.rsa_encrypt:
                    encoded_token = jwt.encode(payload, key, algorithm=algorithm)
                else:
                    message = "The algorithm RS256 is not supported, " \
                        "please verify the loading of your key or something relationated with the key"
                    self.gen_abort_error(message, 500)
        except Exception as ex:
            print(f"The following ERROR occurred in {__file__}: {ex}")
            encoded_token = None
        return encoded_token

    def jwt_claims(self, func: Callable[[None], dict[str, datetime]]) -> None:
        """
        Decorator to add the claims to the JWT payload, default fields are:
        - username: username of the user
        - password: password of the user
        But can be changed by the user in the creation of the object of this class
        You should add the next keys inside the dictionary but are not obligatory:
        - exp: expiration time of the JWT
        - iat: issued at time of the JWT
        - leeway: leeway time of the JWT
        - iss: issuer of the JWT

        Args:
        - func: function to be decorated

        Returns:
        - Callable: the function to wrap should return a dictionary with the extra fields

        ### Example
        ```python
        @gen_jwt.jwt_claims
        def jwt_claims() -> dict:
            claims = {
                "exp": dt.datetime.now(tz=dt.timezone.utc) + dt.timedelta(seconds=30),
                "iat": dt.datetime.now(tz=dt.timezone.utc)
            }
            return claims
        ```
        """
        self.jwt_fields_attr = func()

    def verify_bauth_credentials(self, func: Callable[[str, str], bool]) -> Callable[[str, str], bool]:
        """
        Decorator to get the basic auth credentials.

        Args:
        - func: function to be decorated

        Returns:
        - Callable: the function to wrap that returns a boolean, True if the credentials are correct, False if not
        User should implement the function to validate the credentials and return the correct boolean, but a little example below.

        ### Example
        ```python
        @gen_jwt.verify_bauth_credentials
        def get_basic_auth_credentials2(username: str, password: str) -> dict:
            # Use the username and password to authenticate the user in the way you want-
            # and return true if the user is authenticated
            return username == "your_username_from_somewhere" and password == "your_password_from_somewhere"
        ```
        """
        self.basic_auth_callback = func
        return func

    def generate_jwt(self, func=None, roles=None) -> Callable[[str], str]:
        """
        Decorator to generate the JWT token through the function of the endpoint that responds the token

        Args:
        - func: function to be decorated
        - roles: roles to verify

        Returns:
        - Callable: the function to wrap that returns the encoded token

        ### Example
        ```python
        @app.route("/endpoint", methods=["Method_you_want"])
        @gen_jwt.generate_jwt(roles=["role1", "role2"])
        def gen_token(token) -> Response:
            response = {
                "status": "success",
                "token": token
            }
            return make_response(jsonify(response)), HTTPStatus.OK.value
        ```
        """
        if func is not None and (roles is not None):
            raise ValueError("role and optional are the only supported arguments")
        def func_to_receive(func):
            """
            Secondary wrapper of the decorator that receives the function to be decorated

            Args:
            - func: function to be decorated

            Returns:
            - Callable: the function to wrap that returns the encoded token
            """
            @wraps(func)
            def wrapper(*args, **kwargs):
                """
                Main wrapper of the decorator

                Args:
                - args: arguments of the function
                - kwargs: keyword arguments of the function

                Returns:
                - Callable: the function to wrap that returns the encoded token
                """
                if self.enc_dec_jwt_callback is None:
                    self.gen_abort_error("get_decode_jwt_attributes decorator and function to verify password and username is not set", 500)
                else:
                    grant_credentials_access = self.__dec_set_basic_auth()
                    if grant_credentials_access[0]:
                        self.verify_user_roles(roles, grant_credentials_access[1]["username"])
                        jwt_payload = self.__create_jwt_payload(grant_credentials_access[1])
                        token = self.__encode_jwt(jwt_payload)
                    else:
                        self.gen_abort_error("The credentials are not correct", 401)

                return self.ensure_sync(func)(token, *args, **kwargs)
            return wrapper
        if func:
            return func_to_receive(func)
        return func_to_receive

class DecJwt(Core):
    """
    Class to decode the JWT token, the user should set the key and algorithm to decode the JWT-
    and also the claims that will be added to the JWT payload.

    Args:
    - token_as_attr: boolean to specify if the token will be set as attribute of the class

    Returns:
    - None
    """
    token: dict = None
    def __init__(self, token_as_attr: bool = False) -> None:
        """
        Constructor of the class.

        Args:
        - token_as_attr: boolean to specify if the token will be set as attribute of the class

        Returns:
        - None
        """
        self.token_as_attr: bool = token_as_attr
        self.credentials_success_callback: bool = None
        self.get_jwt_claims_to_verify_callback: list[str] = None

    def __decode_jwt(self) -> Optional[dict]:
        """
        Decode the JWT token using the key and algorithm specified in the enc_dec_jwt_config decorator
        that returns the dictionary with the configuration.

        Args:
        - None

        Returns:
        - dict: decoded token or None if an error occurred
        """
        auth_header = request.headers.get("Authorization")
        if auth_header is None:
            self.gen_abort_error("Authorization header is missing", HTTPStatus.BAD_REQUEST.value)
        auth_header = auth_header.split(" ")
        token = auth_header[1]
        del auth_header
        self.verify_dict_config("jwt")
        key = self.enc_dec_jwt_callback["key"]
        algorithm = self.enc_dec_jwt_callback["algorithm"]
        try:
            if algorithm == "HS256":
                decoded_token = jwt.decode(token, key, algorithms=[algorithm])
            elif algorithm == "RS256":
                decoded_token = jwt.decode(token, key, algorithms=[algorithm])
            else:
                message = "The algorithm RS256 is not supported, " \
                    "please verify the loading of your key or something relationated with the key"
                self.gen_abort_error(message, 500)
        except Exception as ex:
            print(f"The following ERROR occurred in {__file__}: {ex}")
            decoded_token = None
        return decoded_token

    def __verify_token(self, token: dict) -> None:
        """
        Verify the token, if its None the something went wrong with the decoding of the token.
        If the token is not None, then verify the claims if you implement the get_jwt_claims_to_verify decorator.
        By default the method verify if there is at least one claim inside jwt, if not then invalid token error will appear.

        Args:
        - token: token to verify

        Returns:
        - None
        """
        if token is None:
            self.gen_abort_error("Invalid token", 401)
        else:
            if self.get_jwt_claims_to_verify_callback is not None:
                claims = self.get_jwt_claims_to_verify_callback
                for claim in claims:
                    if claim not in token:
                        self.gen_abort_error(f"The claim {claim} is not in the token", HTTPStatus.BAD_REQUEST.value)
            if len(token) < 1:
                self.gen_abort_error("Invalid token", 401)
            if self.personal_credentials is not None:
                per_username = self.personal_credentials[0]
                per_password = self.personal_credentials[1]
                if (per_username not in token) or (per_password not in token):
                    self.gen_abort_error("Invalid token", 401)
            else:
                if ("username" not in token) or ("password" not in token):
                    self.gen_abort_error("Invalid token", 401)
            keys_to_validate = self.get_jwt_claims_to_verify_callback
            for key in keys_to_validate:
                if key not in token:
                    self.gen_abort_error("Credentials to validate for authentication inside token are not correct", 401)

    def __authenticate_credentials(self, token: dict[str, str]) -> bool:
        """
        Verify the credentials of the user, if the credentials are not correct then the user will be unauthorized

        Args:
        - token: token to verify the credentials

        Returns:
        - bool: True if the credentials are correct, False if not
        """
        if self.credentials_success_callback is None:
            self.gen_abort_error("get_credentials_success decorator is not set", 500)
        if self.personal_credentials is None:
            username_jwt = token["username"]
            password_jwt = token["password"]
        else:
            username_jwt = token[self.personal_credentials[0]]
            password_jwt = token[self.personal_credentials[1]]
        return self.ensure_sync(self.credentials_success_callback)(username_jwt, password_jwt)

    def __set_token_as_attr(self, token: dict) -> None:
        """
        Method to set the token as an attribute of the class

        Args:
        - token: token to set as attribute

        Returns:
        - None
        """
        if self.token_as_attr:
            self.token = token

    def get_jwt_claims_to_verify(self, func: Callable[[None], list[str]]) -> None:
        """
        Decorator to get the claims to verify in the token

        Args:
        - func: function to be decorated, should return a list of the claims to verify

        Returns:
        - Callable: the function to wrap that returns the a boolean field

        ### Registered claims
        The JWT specification defines seven reserved claims that are not required, but are recommended to allow interoperability with third-party applications. These are:

        - iss (issuer): Issuer of the JWT
        - sub (subject): Subject of the JWT (the user)
        - aud (audience): Recipient for which the JWT is intended
        - exp (expiration time): Time after which the JWT expires
        - nbf (not before time): Time before which the JWT must not be accepted for processing
        - iat (issued at time): Time at which the JWT was issued; can be used to determine age of the JWT
        - jti (JWT ID): Unique identifier; can be used to prevent the JWT from being replayed (allows a token to be used only once)

        More about claims [here](https://auth0.com/docs/secure/tokens/json-web-tokens/json-web-token-claims)

        ### Example
        ```python
        @dec_jwt.get_jwt_claims_to_verify
        def get_jwt_claims():
            return ["iat", "sub"]
        ```
        """
        self.get_jwt_claims_to_verify_callback = func()

    def verify_jwt_credentials(self, func: Callable[[str, str], bool]) -> Callable[[str, str], bool]:
        """
        Decorator to get the credentials from database or whatever part
        to verify the token fields later.

        Args:
        - func: function to be decorated

        Returns:
        - Callable: the function to wrap that returns a boolean, True if the credentials are correct, False if not.

        IMPORTANT: The dictionary keys of this decorator should be the same as the claims of the token that you want to validate.

        ### Example
        ```python
        @dec_jwt.verify_jwt_credentials
        def get_credentials_success(username: str, password: str) -> bool:
            # Use the username and password to authenticate the user in the way you want-
            # and return true if the user is authenticated
            return username == "your_username_from_somewhere" and password == "your_password_from_somewhere"
        ```
        """
        self.credentials_success_callback = func
        return func

    def login_required(self, func=None, roles=None) -> Callable[[str], str]:
        """
        Decorator to verify the JWT token through the function of the endpoints that
        are requested by the user, also validates the roles setted in the endpoint.

        Args:
        - func: function to be decorated
        - roles: roles to verify

        Returns:
        - Callable: the function to wrap that returns the encoded token
        """
        if func is not None and (roles is not None):
            raise ValueError("role and optional are the only supported arguments")
        def func_to_receive(func) -> Callable[[str], str]:
            """
            Secondary wrapper of the decorator that receives the function to be decorated

            Args:
            - func: function to be decorated

            Returns:
            - Callable: the function to wrap that returns the encoded token
            """
            @wraps(func)
            def wrapper(*args, **kwargs) -> Callable[[str], str]:
                """
                Main wrapper of the decorator

                Args:
                - args: arguments of the function
                - kwargs: keyword arguments of the function

                Returns:
                - Callable: the function to wrap that returns the encoded token
                """
                if self.enc_dec_jwt_callback is None:
                    self.gen_abort_error("get_decode_jwt_attributes decorator and function to verify password and username is not set", 500)
                else:
                    token = self.__decode_jwt()
                    self.__verify_token(token)

                    grant_access = self.__authenticate_credentials(token)
                    if not grant_access:
                        self.gen_abort_error("The credentials are not correct", 401)
                    if self.personal_credentials is not None:
                        self.verify_user_roles(roles, token[self.personal_credentials[0]])
                    else:
                        self.verify_user_roles(roles, token["username"])
                    self.__set_token_as_attr(token)

                return self.ensure_sync(func)(*args, **kwargs)
            return wrapper
        if func:
            return func_to_receive(func)
        return func_to_receive
