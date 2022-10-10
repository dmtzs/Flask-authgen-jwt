"""
flask_authgen_jwt
==================
This module provides creation of new jwt also using basic auth to get the jwt and decode of the jwt.
:copyright: (C) 2022 by Diego Martinez Sanchez and Guillermo Ortega Romo.
:license:   MIT, see LICENSE for more details.
"""

#TODO: Verify at the end of the core implementation the better way to implement error handlers so you can manipulate the error messages

try:
    import jwt
    from functools import wraps
    from base64 import b64decode
    from flask import request, current_app, abort, make_response, jsonify
except ImportError as eImp:
    print(f"The following import ERROR occurred in {__file__}: {eImp}")

class Core():
    enc_dec_jwt_callback: dict = None
    get_user_roles_callback: list = None

    def enc_dec_jwt_config(self, func):
        """Decorator to verify the JWT token
        :param f: function to be decorated
        :return: the function to wrap should return a dictionary with the following keys:
            - key: key to decode the JWT
            - algorithm: algorithm to decode the JWT """
        self.enc_dec_jwt_callback = func()
        return func

    def verify_dict_config(self, config: str):
        if config == "jwt":
            claims = ["key", "algorithm", "expiration"]
            for claim in claims:
                if claim not in self.enc_dec_jwt_callback:
                    self.gen_abort_error(f"The claim {claim} is not in the dictionary", 400)
        elif config == "basic_auth":
            claims = ["username", "password"]
            for claim in claims:
                if claim not in self.basic_auth_callback:
                    self.gen_abort_error(f"The claim {claim} is not in the dictionary", 400)

    def verify_user_roles(self, roles: list):
        if roles is not None:
            if self.get_user_roles_callback is None:
                self.gen_abort_error("get_user_roles decorator and function is not defined is not defined", 500)
            else:
                user_roles = self.get_user_roles_callback
                # if not set(roles).issubset(set(user_roles)):
                role_flag = False
                for role in user_roles:
                    if role in roles:
                        role_flag = True
                        break
                if not role_flag:
                    self.gen_abort_error("User does not have the required roles", 403)
    
    def get_user_roles(self, func):
        """Decorator to get the user roles
        :param f: function to be decorated
        :return: user roles as a list"""
        self.get_user_roles_callback = func()
        return func

    def gen_abort_error(self, error: str, status_code: int):
        abort(make_response(jsonify({"error": error}), status_code))

    def ensure_sync(self, func):
        try:
            return current_app.ensure_sync(func)
        except AttributeError:
            return func

class GenJwt(Core):
    def __init__(self):
        self.jwt_extra_fields: dict = None
        self.basic_auth_callback: dict = None

    def __create_jwt_payload(self):
        payload = self.basic_auth_callback
        payload["expiration"] = self.enc_dec_jwt_callback["expiration"]
        if self.jwt_extra_fields:
            payload.update(self.jwt_extra_fields)
        return payload
    
    def __verify_basic_auth(self):
        auth_header = request.headers.get("Authorization")
        auth_header = auth_header.split(" ")
        if auth_header[0] != "Basic":
            self.gen_abort_error("Authorization header must be Basic", 400)
        credentials = auth_header[1]
        credentials = b64decode(credentials).decode("utf-8")
        credentials = credentials.split(":")
        if len(credentials) != 2:
            self.gen_abort_error("Authorization header must be Basic with user and password only", 400)
        self.verify_dict_config("basic_auth")
        username = self.basic_auth_callback["username"]
        password = self.basic_auth_callback["password"]
        if credentials[0] != username or credentials[1] != password:
            self.gen_abort_error("User or password is not correct", 401)
    
    def __encode_jwt(self, payload):
        self.verify_dict_config("jwt")
        key = self.enc_dec_jwt_callback["key"]
        algorithm = self.enc_dec_jwt_callback["algorithm"]
        try:
            encoded_token = jwt.encode(payload, key, algorithm=algorithm)
        except Exception as ex:
            print(f"The following ERROR occurred in {__file__}: {ex}")
            encoded_token = None
        return encoded_token
    
    # def get_json_body(self):# Could be useful later for personalized basic auth config
    #     if not request.is_json:
    #         self.gen_abort_error("Request body must be JSON", 400)
    #     return request.get_json()

    def add_jwt_extra_fields(self, func):
        """Decorator to add extra fields to the JWT payload, default fields are:
        - username: username of the user
        - password: password of the user
        - exp: expiration time of the JWT

        :param func: function to be decorated
        :return: the function to wrap should return a dictionary with the extra fields"""
        self.jwt_extra_fields = func()
        return func
    
    def get_basic_auth_credentials(self, func):
        self.basic_auth_callback = func()
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
                    self.__verify_basic_auth()
                    jwt_payload = self.__create_jwt_payload()
                    token = self.__encode_jwt(jwt_payload)
                    self.verify_user_roles(roles)

                return self.ensure_sync(func)(token, *args, **kwargs)
            return wrapper
        if func:
            return func_to_receive(func)
        return func_to_receive

class DecJwt(Core):
    def __init__(self):
        self.enc_dec_jwt_callback: dict = None
        self.get_jwt_claims_to_verify_callback: list = None
    
    def __decode_jwt(self):
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

    def __verify_token(self, token):
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
                    self.verify_user_roles(roles)

                return self.ensure_sync(func)(*args, **kwargs)
            return wrapper
        if func:
            return func_to_receive(func)
        return func_to_receive