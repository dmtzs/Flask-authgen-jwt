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
    import typing
    import traceback
    from functools import wraps
    from base64 import b64decode
    from flask import request, current_app, abort, make_response, jsonify
except ImportError as eImp:
    print(f"The following import ERROR occurred in {__file__}: {eImp}")

class Core():
    basic_auth_callback: dict = None
    enc_dec_jwt_callback: dict = None
    get_user_roles_callback: list = None

    def enc_dec_jwt_config(self, func) -> typing.Callable:
        """Decorator to verify the JWT token
        :param f: function to be decorated
        :return: the function to wrap should return a dictionary with the following keys:
            - key: key to decode the JWT
            - algorithm: algorithm to decode the JWT """
        self.enc_dec_jwt_callback = func()
        return func

    def verify_dict_config(self, config: str):
        """Method that veryfies the JWT configuration generator and for basic auth
        :param config: str to identify which configuration to verify"""
        if config == "jwt":
            claims = ["key", "algorithm"]
            for claim in claims:
                if claim not in self.enc_dec_jwt_callback:
                    self.gen_abort_error(f"The claim {claim} is not in the dictionary", 400)
        elif config == "basic_auth":
            claims = ["username", "password"]
            for claim in claims:
                if claim not in self.basic_auth_callback:
                    self.gen_abort_error(f"The claim {claim} is not in the dictionary", 400)

    def verify_user_roles(self, roles: list):
        """Method to verify the user roles if are correct
        :param roles: list of roles to verify against the user roles callback"""
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
    
    def get_user_roles(self, func) -> typing.Callable:
        """Decorator to get the user roles
        :param f: function to be decorated
        :return: user roles as a list"""
        self.get_user_roles_callback = func()
        return func

    def gen_abort_error(self, error: str, status_code: int):
        """Method to generate the abort error with the error message and status code
        :param error: error message in string format
        :param status_code: status code in int format"""
        abort(make_response(jsonify({"error": error}), status_code))

    def ensure_sync(self, func) -> typing.Callable:
        """Decorator to ensure the function is synchronous
        :param f: function to be decorated
        :return: the function to wrap"""
        try:
            return current_app.ensure_sync(func)
        except AttributeError:
            return func

class GenJwt(Core):
    def __init__(self, default_jwt_claims: bool = True, registered_claims_only: bool = True, complete_traceback_genjwt: bool = False):
        self.jwt_fields_attr: dict = None
        self.default_jwt_claims: bool = default_jwt_claims
        self.registered_claims_only: bool = registered_claims_only
        self.complete_traceback_genjwt: bool = complete_traceback_genjwt
    
    def __validate_registered_claims(self):
        """
        Method to validate the registered claims if registered_claims_only is True.
        Cause this means that the user can only use the registered(standard) claims.
        """
        registered_claims = ["iss", "sub", "aud", "exp", "nbf", "iat", "jti"]
        for claim in self.jwt_fields_attr:
            if claim not in registered_claims:
                self.gen_abort_error(f"The claim {claim} is not a registered claim", 400)

    def __create_jwt_payload(self) -> dict:
        """
        Method to create the JWT payload but still not encoded
        :return: JWT payload as a dictionary
        """
        if not self.jwt_fields_attr:
            self.gen_abort_error("jwt_claims decorator and function is not defined", 500)
        if self.registered_claims_only:
            self.__validate_registered_claims()
            payload = {}
            payload.update(self.jwt_fields_attr)
        else:
            if self.default_jwt_claims and not self.registered_claims_only:
                payload = self.basic_auth_callback
                payload.update(self.jwt_fields_attr)
            else:
                payload = self.jwt_fields_attr
            
        return payload
    
    def __verify_basic_auth(self):
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
        self.verify_dict_config("basic_auth")
        username = self.basic_auth_callback["username"]
        password = self.basic_auth_callback["password"]
        if credentials[0] != username or credentials[1] != password:
            self.gen_abort_error("User or password is not correct", 401)
    
    def __encode_jwt(self, payload) -> tuple[str, None]:
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

    def jwt_claims(self, func):
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
    
    def get_basic_auth_credentials(self, func) -> typing.Callable:
        """Decorator to get the basic auth credentials
        :param f: function to be decorated, should return a dictionary with the following keys:
            - username: username of the user
            - password: password of the user
        :return: the function to wrap that returns the dictionary specified above"""
        self.basic_auth_callback = func()
        return func

    def generate_jwt(self, func=None, roles=None):
        if func is not None and (roles is not None):
            raise ValueError("role and optional are the only supported arguments")
        def func_to_receive(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                try:
                    if self.enc_dec_jwt_callback is None:
                        self.gen_abort_error("get_decode_jwt_attributes decorator and function to verify password and username is not set", 500)
                    else:
                        self.__verify_basic_auth()
                        jwt_payload = self.__create_jwt_payload()
                        token = self.__encode_jwt(jwt_payload)
                        self.verify_user_roles(roles)

                    return self.ensure_sync(func)(token, *args, **kwargs)
                except Exception:
                    if self.complete_traceback_genjwt:
                        # This can be used to return traceback using the API for DEV purposes.
                        error = traceback.format_exc()
                        self.gen_abort_error(str(error), 500)
                    else:
                        # Otherwise this is the default which returns an internal server error to the API
                        # and prints the traceback to the console.
                        print(f"The following ERROR occurred in {__file__}: {traceback.format_exc()}")
                        self.gen_abort_error("Internal server error", 500)
            return wrapper
        if func:
            return func_to_receive(func)
        return func_to_receive

class DecJwt(Core):
    token: dict = None
    def __init__(self, token_as_attr: bool = False, complete_traceback_decjwt: bool = False):
        self.token_as_attr: bool = token_as_attr
        self.credentials_success_callback: dict = None
        self.get_jwt_claims_to_verify_callback: list = None
        self.complete_traceback_decjwt: bool = complete_traceback_decjwt
    
    def __decode_jwt(self) -> tuple[str, None]:
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
    
    def __authenticate_credentials(self, token):
        """
        Verify the credentials of the user, if the credentials are not correct then the user will be unauthorized
        :param token: token to verify the credentials
        """
        if self.credentials_success_callback is None:
            self.gen_abort_error("get_credentials_success decorator is not set", 500)
        else:
            keys_to_validate = self.get_jwt_claims_to_verify_callback.keys()
            for key in keys_to_validate:
                if self.credentials_success_callback[key] != token[key]:
                    self.gen_abort_error("Credentials to validate for authentication inside token are not correct", 401)

    def __set_token_as_attr(self, token):
        """
        Method to set the token as an attribute of the class
        :param token: token to set as attribute
        """
        if self.token_as_attr:
            self.token = token

    def get_jwt_claims_to_verify(self, func) -> typing.Callable:
        """Decorator to get the claims to verify in the token
        :param func: function to be decorated, should return a list of the claims to verify
        :return: the function to wrap that returns the a boolean field"""
        self.get_jwt_claims_to_verify_callback = func()
        return func

    def verify_jwt_credentials(self, func) -> typing.Callable:
        """Decorator to get the credentials from database or whatever part
        to verify the token fields later
        :param func: function to be decorated
        :return: the function to wrap that returns the dictionary with the credentials.
        the dictionary keys of this decorator should be the same as the claims of the token that you want to validate"""
        self.credentials_success_callback = func()
        return func
    
    def login_required(self, func=None, roles=None):
        if func is not None and (roles is not None):
            raise ValueError("role and optional are the only supported arguments")
        def func_to_receive(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                try:
                    if self.enc_dec_jwt_callback is None:
                        self.gen_abort_error("get_decode_jwt_attributes decorator and function to verify password and username is not set", 500)
                    else:
                        token = self.__decode_jwt()
                        self.__verify_token(token)
                        self.verify_user_roles(roles)
                        self.__authenticate_credentials(token)
                        self.__set_token_as_attr(token)

                    return self.ensure_sync(func)(*args, **kwargs)
                except Exception:
                    error = traceback.format_exc()
                    if self.complete_traceback_decjwt:
                        # This can be used to return traceback using the API for DEV purposes.
                        self.gen_abort_error(str(error), 500)
                    else:
                        # Otherwise this is the default which returns an internal server error to the API
                        # and prints the traceback to the console.
                        print(f"The following ERROR occurred in {__file__}: {error}")
                        self.gen_abort_error("Internal server error", 500)
            return wrapper
        if func:
            return func_to_receive(func)
        return func_to_receive