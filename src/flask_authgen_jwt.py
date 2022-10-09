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
    from flask import request, current_app, abort, make_response, Response
except ImportError as eImp:
    print(f"The following import ERROR occurred in {__file__}: {eImp}")

class Core():
    auth_error_callback = None
    
    def error_handler(self, func):
        @wraps(func)
        def decorated(*args, **kwargs):
            res = self.ensure_sync(func)(*args, **kwargs)
            check_status_code = not isinstance(res, (tuple, Response))
            res = make_response(res)
            if check_status_code and res.status_code == 200:
                # if user didn't set status code, use 401
                res.status_code = 401
            return res
        self.auth_error_callback = decorated
        return decorated
    
    def ensure_sync(self, func):
        try:
            return current_app.ensure_sync(func)
        except AttributeError:
            return func

class GenJwt(Core):
    def __init__(self):
        self.encode_jwt_callback: dict = None

    def get_encode_jwt_attributes(self, func):
        """Decorator to verify the JWT token
        :param f: function to be decorated
        :return: the function to wrap should return a dictionary with the following keys:
            - key: key to decode the JWT
            - algorithm: algorithm to decode the JWT """
        self.encode_jwt_callback = func()
        return func

class DecJwt(Core):
    def __init__(self):
        self.get_user_roles_callback: list = None
        self.decode_jwt_callback: dict = None
        self.get_jwt_claims_to_verify_callback: list = None

    def __verify_dict_config(self):
        claims = ["key", "algorithm"]
        for claim in claims:
            if claim not in self.decode_jwt_callback:
                abort(400, f"The claim {claim} is not in the dictionary")
    
    def __decode_jwt(self):
        auth_header = request.headers.get("Authorization")
        auth_header = auth_header.split(" ")
        token = auth_header[1]
        del auth_header
        self.__verify_dict_config()
        key = self.decode_jwt_callback["key"]
        algorithm = self.decode_jwt_callback["algorithm"]
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
            abort(401, "Invalid token")
        else:
            if self.get_jwt_claims_to_verify_callback is not None:
                claims = self.get_jwt_claims_to_verify_callback
                for claim in claims:
                    if claim not in token:
                        abort(401, f"The claim {claim} is not in the token")
            if len(token) < 1:
                abort(401, "Invalid token")

    def get_user_roles(self, func):
        """Decorator to get the user roles
        :param f: function to be decorated
        :return: user roles as a list"""
        self.get_user_roles_callback = func()
        return func
    
    def get_decode_jwt_attributes(self, func):
        """Decorator to verify the JWT token
        :param f: function to be decorated
        :return: the function to wrap should return a dictionary with the following keys:
            - key: key to decode the JWT
            - algorithm: algorithm to decode the JWT """
        self.decode_jwt_callback = func()
        return func
    
    def login_required(self, func=None, roles=None):
        if func is not None and (roles is not None):
            raise ValueError("role and optional are the only supported arguments")
        def func_to_receive(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                if self.decode_jwt_callback is None:
                    return abort(500, "The function to verify password and username is not set")
                else:
                    token = self.__decode_jwt()
                    self.__verify_token(token)

                if roles is not None:
                    if self.get_user_roles_callback is None:
                        return abort(500, "get_user_roles decorator and function is not defined is not defined")
                    else:
                        user_roles = self.get_user_roles_callback
                        if not set(roles).issubset(set(user_roles)):
                            return abort(401, "User is not authorized to access this resource")
                return self.ensure_sync(func)(*args, **kwargs)
            return wrapper
        if func:
            return func_to_receive(func)
        return func_to_receive