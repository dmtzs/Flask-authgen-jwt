"""
flask_authgen_jwt
==================
This module provides creation of new jwt also using basic auth to get the jwt and decode of the jwt.
:copyright: (C) 2022 by Diego Martinez Sanchez and Guillermo Ortega Romo.
:license:   MIT, see LICENSE for more details.
"""

try:
    from functools import wraps
    from base64 import b64decode
    from flask import request, abort, current_app
except ImportError as eImp:
    print(f"The following import ERROR occurred in {__file__}: {eImp}")

class GenJwt():
    def __init___(self):
        pass

class DecJwt():
    def __init__(self):
        self.get_user_roles_callback: list = None
        self.verify_credentials_callback: bool = None

    def get_user_roles(self, func):
        """Decorator to get the user roles
        :param f: function to be decorated
        :return: user roles as a list"""
        self.get_user_roles_callback = func()
        print(f"roles results: {self.get_user_roles_callback}")
        return func
    
    def decode_jwt_attributes(self, func):
        """Decorator to verify the JWT token
        :param f: function to be decorated
        :return: the fucnction to wrap should return a dictionary with the following keys:
            - key: key to decode the JWT
            - algorithm: algorithm to decode the JWT """
        self.verify_credentials_callback = func()
        return func
    
    def login_required(self, func=None, roles=None):
        if func is not None and (roles is not None):
            raise ValueError("role and optional are the only supported arguments")
        def func_to_receive(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                if self.verify_credentials_callback is None:
                    return abort(500, "The function to verify password and username is not set")
                elif not self.ensure_sync(self.verify_credentials_callback):
                    abort(401, "The credentials are not valid")

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
    
    def ensure_sync(self, func):
        try:
            return current_app.ensure_sync(func)
        except AttributeError:
            return func