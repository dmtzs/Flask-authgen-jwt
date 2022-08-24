"""
flask_authgen_jwt
==================
This module provides creation of new jwt also using basic auth to get the jwt and decode of the jwt.
:copyright: (C) 2022 by Diego Martinez and Guillermo Ortega.
:license:   MIT, see LICENSE for more details.
"""

try:
    from base64 import b64decode
    from flask import request, abort
except ImportError as eImp:
    print(f"The following import ERROR occurred in {__file__}: {eImp}")

class GenJwt():
    pass

class DecJwt():
    pass