try:
    from flask import Flask
    import flask_authgen_jwt
except ImportError as eImp:
    print(f"The following import ERROR occurred in {__file__}: {eImp}")

app = Flask(__name__)
gen_auth = flask_authgen_jwt.GenJwt()
auth = flask_authgen_jwt.DecJwt()

from app import routes