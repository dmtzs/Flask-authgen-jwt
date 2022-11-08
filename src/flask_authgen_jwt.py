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
    from typing import Callable, Optional
    from flask import request, current_app, abort, make_response, jsonify
except ImportError as eImp:
    print(f"The following import ERROR occurred in {__file__}: {eImp}")

class Core():
    basic_auth_callback: Callable[[str, str], bool] = None
    enc_dec_jwt_callback: dict = None
    get_user_roles_callback: list = None

    def enc_dec_jwt_config(self, func: Callable[[None], dict]) -> None:
        """Decorator to verify the JWT token
        :param f: function to be decorated
        :return: the function to wrap should return a dictionary with the following keys:
            - key: key to decode the JWT
            - algorithm: algorithm to decode the JWT """
        self.enc_dec_jwt_callback = func()
        return func

    def verify_dict_config(self, config: str) -> None:
        """Method that veryfies the JWT configuration generator and for basic auth
        :param config: str to identify which configuration to verify"""
        if config == "jwt":
            claims = ["key", "algorithm"]
            for claim in claims:
                if claim not in self.enc_dec_jwt_callback:
                    self.gen_abort_error(f"The claim {claim} is not in the dictionary", 400)

    def verify_user_roles(self, roles: list, user: str) -> None:
        """Method to verify the user roles if are correct
        :param roles: list of roles to verify against the user roles callback"""
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
        """Decorator to get the user roles by the user that was received from the JWT or basic auth.
        To the function you will decorate with this decorator you will have available the user variable
        :param f: function to be decorated
        :return: user roles as a list"""
        self.get_user_roles_callback = func
        return func

    def gen_abort_error(self, error: str, status_code: int) -> None:
        """Method to generate the abort error with the error message and status code
        :param error: error message in string format
        :param status_code: status code in int format"""
        abort(make_response(jsonify({"error": error}), status_code))

    def ensure_sync(self, func) -> Callable:
        """Decorator to ensure the function is synchronous
        :param f: function to be decorated
        :return: the function to wrap"""
        try:
            return current_app.ensure_sync(func)
        except AttributeError:
            return func

class GenJwt(Core):
    def __init__(self) -> None:
        self.jwt_fields_attr: dict = None

    def __create_jwt_payload(self, bauth_credentials: dict) -> dict:
        """
        Method to create the JWT payload but still not encoded
        :return: JWT payload as a dictionary
        """
        if not self.jwt_fields_attr:
            self.gen_abort_error("jwt_claims decorator and function is not defined", 500)
        payload = bauth_credentials
        payload.update(self.jwt_fields_attr)
            
        return payload
    
    def __dec_set_basic_auth(self) -> None:
        """
        Method to decode and verify the basic auth credentials in the expected format
        """
        auth_header = request.headers.get("Authorization")
        auth_header = auth_header.split(" ")
        if auth_header[0] != "Basic":
            self.gen_abort_error("Authorization header must be Basic", 400)
        credentials = auth_header[1]
        credentials = b64decode(credentials).decode("utf-8")
        credentials = credentials.split(":")
        if len(credentials) != 2:
            self.gen_abort_error("Authorization header must be Basic with user and password only", 400)
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
    
    def __encode_jwt(self, payload) -> Optional[str]:
        """
        Method to encode the JWT token using the key and algorithm specified in the enc_dec_jwt_config decorator
        that returns the dictionary with the configuration.
        :return: the encoded token or None if an error occurred
        """
        self.verify_dict_config("jwt")
        key = self.enc_dec_jwt_callback["key"]
        algorithm = self.enc_dec_jwt_callback["algorithm"]
        try:
            encoded_token = jwt.encode(payload, key, algorithm=algorithm)
        except Exception as ex:
            print(f"The following ERROR occurred in {__file__}: {ex}")
            encoded_token = None
        return encoded_token

    def jwt_claims(self, func: Callable[[None], dict]) -> None:
        """Decorator to add the claims to the JWT payload, default fields are:
        - username: username of the user
        - password: password of the user
        But can be changed by the user in the creation of the object of this class
        You should add the next keys inside the dictionary but are not obligatory:
        - exp: expiration time of the JWT
        - iat: issued at time of the JWT
        - leeway: leeway time of the JWT
        - iss: issuer of the JWT

        :param func: function to be decorated
        :return: the function to wrap should return a dictionary with the extra fields"""
        self.jwt_fields_attr = func()
    
    def verify_bauth_credentials(self, func: Callable[[str, str], bool]) -> Callable[[str, str], bool]:
        """Decorator to get the basic auth credentials
        :param f: function to be decorated, should return a boolean:
        :return: the function to wrap that returns a boolean, True if the credentials are correct, False if not
        User should implement the function to validate the credentials and return the correct boolean"""
        self.basic_auth_callback = func
        return func

    def generate_jwt(self, func=None, roles=None):
        if func is not None and (roles is not None):
            raise ValueError("role and optional are the only supported arguments")
        def func_to_receive(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
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
    token: dict = None
    def __init__(self, token_as_attr: bool = False) -> None:
        self.token_as_attr: bool = token_as_attr
        self.credentials_success_callback: bool = None
        self.get_jwt_claims_to_verify_callback: list[str] = None
    
    def __decode_jwt(self) -> Optional[str]:
        """
        Decode the JWT token using the key and algorithm specified in the enc_dec_jwt_config decorator
        that returns the dictionary with the configuration.
        :return: the decoded token or None if an error occurred
        """
        auth_header = request.headers.get("Authorization")
        auth_header = auth_header.split(" ")
        token = auth_header[1]
        del auth_header
        self.verify_dict_config("jwt")
        key = self.enc_dec_jwt_callback["key"]
        algorithm = self.enc_dec_jwt_callback["algorithm"]
        try:
            decoded_token = jwt.decode(token, key, algorithms=[algorithm])
        except Exception as ex:
            print(f"The following ERROR occurred in {__file__}: {ex}")
            decoded_token = None
        return decoded_token

    def __verify_token(self, token) -> None:
        """Verify the token, if its None the something went wrong with the decoding of the token.
        If the token is not None, then verify the claims if you implement the get_jwt_claims_to_verify decorator.
        By default the method verify if there is at least one claim inside jwt, if not then invalid token error will appear.
        :param token: token to verify"""
        if token is None:
            self.gen_abort_error("Invalid token", 401)
        else:
            if self.get_jwt_claims_to_verify_callback is not None:
                claims = self.get_jwt_claims_to_verify_callback
                for claim in claims:
                    if claim not in token:
                        self.gen_abort_error(f"The claim {claim} is not in the token", 400)
            if len(token) < 1:
                self.gen_abort_error("Invalid token", 401)
            if ("username" not in token) or ("password" not in token):
                self.gen_abort_error("Invalid token", 401)
            keys_to_validate = self.get_jwt_claims_to_verify_callback
            for key in keys_to_validate:
                if key not in token:
                    self.gen_abort_error("Credentials to validate for authentication inside token are not correct", 401)
    
    def __authenticate_credentials(self, token) -> None:
        """
        Verify the credentials of the user, if the credentials are not correct then the user will be unauthorized
        :param token: token to verify the credentials
        """
        if self.credentials_success_callback is None:
            self.gen_abort_error("get_credentials_success decorator is not set", 500)
        username_jwt = token["username"]
        password_jwt = token["password"]
        return self.ensure_sync(self.credentials_success_callback)(username_jwt, password_jwt)

    def __set_token_as_attr(self, token: dict) -> None:
        """
        Method to set the token as an attribute of the class
        :param token: token to set as attribute
        """
        if self.token_as_attr:
            self.token = token

    def get_jwt_claims_to_verify(self, func: Callable[[None], list[str]]) -> None:
        """Decorator to get the claims to verify in the token
        :param func: function to be decorated, should return a list of the claims to verify
        :return: the function to wrap that returns the a boolean field"""
        self.get_jwt_claims_to_verify_callback = func()

    def verify_jwt_credentials(self, func) -> Callable[[str, str], dict]:
        """Decorator to get the credentials from database or whatever part
        to verify the token fields later
        :param func: function to be decorated
        :return: the function to wrap that returns the dictionary with the credentials.
        the dictionary keys of this decorator should be the same as the claims of the token that you want to validate"""
        self.credentials_success_callback = func
        return func
    
    def login_required(self, func=None, roles=None):
        if func is not None and (roles is not None):
            raise ValueError("role and optional are the only supported arguments")
        def func_to_receive(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                if self.enc_dec_jwt_callback is None:
                    self.gen_abort_error("get_decode_jwt_attributes decorator and function to verify password and username is not set", 500)
                else:
                    token = self.__decode_jwt()
                    self.__verify_token(token)
                    self.verify_user_roles(roles, token["username"])

                    grant_access = self.__authenticate_credentials(token)
                    if not grant_access:
                        self.gen_abort_error("The credentials are not correct", 401)
                    self.__set_token_as_attr(token)

                return self.ensure_sync(func)(*args, **kwargs)
            return wrapper
        if func:
            return func_to_receive(func)
        return func_to_receive