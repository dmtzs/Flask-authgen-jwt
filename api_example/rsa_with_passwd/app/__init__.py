try:
    from flask import Flask
    from . import flask_authgen_jwt
except ImportError as eImp:
    print(f"The following import ERROR occurred in {__file__}: {eImp}")

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False
gen_auth = flask_authgen_jwt.GenJwt(rsa_encrypt=True)
auth = flask_authgen_jwt.DecJwt()

from app import routes