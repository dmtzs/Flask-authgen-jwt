"""
flask_authgen_jwt
=================
JWT authentication and generation for Flask.

Issue signed tokens from HTTP Basic Auth (or a JSON body) and protect routes
with a decorator. The signed JWT is what proves authenticity, so credentials
are **never** stored inside the token. Standard claims (``exp``, ``nbf``,
``iat``, ``iss``, ``aud``) are validated by PyJWT with configurable leeway.

Optional features:
- Refresh tokens (``generate_jwt(with_refresh=True)`` / ``refresh_jwt``).
- Per-token revocation via a ``jti`` blocklist (``revoked_token_loader``).
- Verification-key rotation (``keys`` / ``algorithms`` in the config).

:copyright: (C) 2022-2026 by Diego Martinez Sanchez.
:license: MIT, see LICENSE for more details.
"""
from __future__ import annotations

import logging
import uuid
from base64 import b64decode
from binascii import Error as BinasciiError
from datetime import datetime, timedelta, timezone
from functools import wraps
from http import HTTPStatus
from typing import Any, Callable, Optional

import jwt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from flask import abort, current_app, g, jsonify, make_response, request

__all__ = ["Core", "GenJwt", "DecJwt", "get_current_token", "get_current_subject"]

__version__ = "5.0.0"

_TOKEN_G_KEY = "authgen_jwt_token"


def get_current_token() -> Optional[dict[str, Any]]:
    """Return the decoded JWT payload for the current request, or ``None``."""
    try:
        return g.get(_TOKEN_G_KEY)
    except RuntimeError:
        return None


def get_current_subject(subject_field: str = "sub") -> Optional[Any]:
    """Return the subject claim of the current request's token, or ``None``."""
    token = get_current_token()
    return token.get(subject_field) if token else None


class Core:
    """Shared configuration and helpers for token generation and verification."""

    def __init__(self) -> None:
        self._jwt_config_cb: Optional[Callable[[], dict[str, Any]]] = None
        self._roles_cb: Optional[Callable[[Any], list[str]]] = None
        self.subject_claim: str = "sub"

    def enc_dec_jwt_config(
        self, func: Callable[[], dict[str, Any]]
    ) -> Callable[[], dict[str, Any]]:
        """Register the callback returning the signing/verification config.

        Evaluated on every request; must return a dict with at least ``key`` and
        ``algorithm``. Optional: ``keys`` (list, for verification-key rotation),
        ``algorithms`` (list), ``passphrase`` (encrypted private key),
        ``issuer``, ``audience`` and ``leeway``.
        """
        self._jwt_config_cb = func
        return func

    def personal_credentials_field(self, func: Callable[[], Any]) -> Callable[[], Any]:
        """Customize the subject claim name.

        The callback returns the claim name (``str``) or a tuple whose first item
        is the claim name. Kept for backward compatibility; the old password
        field is ignored and is never stored in the token.
        """
        result = func()
        if isinstance(result, (tuple, list)) and result:
            self.subject_claim = result[0]
        elif isinstance(result, str):
            self.subject_claim = result
        return func

    def get_user_roles(
        self, func: Callable[[Any], list[str]]
    ) -> Callable[[Any], list[str]]:
        """Register the callback that returns the roles for a subject."""
        self._roles_cb = func
        return func

    @property
    def logger(self) -> logging.Logger:
        """Return the Flask app logger, or a fallback logger outside app context."""
        try:
            return current_app.logger
        except RuntimeError:
            return logging.getLogger("flask_authgen_jwt")

    def gen_abort_error(self, error: str, status_code: int) -> None:
        """Abort the request with a JSON error body."""
        abort(make_response(jsonify({"error": error}), status_code))

    def ensure_sync(self, func: Callable) -> Callable:
        """Wrap a callback so sync and async functions can both be called."""
        try:
            return current_app.ensure_sync(func)
        except (AttributeError, RuntimeError):
            return func

    def _resolve_config(self) -> dict[str, Any]:
        if self._jwt_config_cb is None:
            self.gen_abort_error(
                "enc_dec_jwt_config is not configured",
                HTTPStatus.INTERNAL_SERVER_ERROR.value,
            )
        config = self.ensure_sync(self._jwt_config_cb)()
        if not isinstance(config, dict):
            self.gen_abort_error(
                "enc_dec_jwt_config must return a dict",
                HTTPStatus.INTERNAL_SERVER_ERROR.value,
            )
        for required in ("key", "algorithm"):
            if required not in config:
                self.gen_abort_error(
                    f"enc_dec_jwt_config is missing '{required}'",
                    HTTPStatus.INTERNAL_SERVER_ERROR.value,
                )
        return config

    def verify_user_roles(
        self, required_roles: Optional[list[str]], subject: Any
    ) -> None:
        """Abort with 403 unless the subject has at least one required role."""
        if not required_roles:
            return
        if self._roles_cb is None:
            self.gen_abort_error(
                "get_user_roles is not configured",
                HTTPStatus.INTERNAL_SERVER_ERROR.value,
            )
        user_roles = self.ensure_sync(self._roles_cb)(subject) or []
        if not any(role in required_roles for role in user_roles):
            self.gen_abort_error(
                "User does not have the required roles", HTTPStatus.FORBIDDEN.value
            )


class GenJwt(Core):
    """Issue signed access (and optional refresh) tokens after validating
    credentials provided via HTTP Basic Auth or a JSON body."""

    def __init__(
        self,
        rsa_encrypt: bool = False,
        json_body_token: bool = False,
        access_ttl_seconds: int = 900,
        refresh_ttl_seconds: int = 2_592_000,
    ) -> None:
        super().__init__()
        self.rsa_encrypt = rsa_encrypt
        self.json_body_token = json_body_token
        self.access_ttl_seconds = access_ttl_seconds
        self.refresh_ttl_seconds = refresh_ttl_seconds
        self._claims_cb: Optional[Callable[[], dict[str, Any]]] = None
        self._bauth_cb: Optional[Callable[[str, str], bool]] = None

    def jwt_claims(
        self, func: Callable[[], dict[str, Any]]
    ) -> Callable[[], dict[str, Any]]:
        """Register the callback returning extra claims for access tokens.

        Evaluated on every generation, so time-based claims like ``exp`` are
        always current.
        """
        self._claims_cb = func
        return func

    def verify_bauth_credentials(
        self, func: Callable[[str, str], bool]
    ) -> Callable[[str, str], bool]:
        """Register the callback validating ``(username, password) -> bool``."""
        self._bauth_cb = func
        return func

    def _extract_credentials(self) -> tuple[str, str]:
        if self.json_body_token:
            if not request.is_json:
                self.gen_abort_error(
                    "Request body must be JSON", HTTPStatus.BAD_REQUEST.value
                )
            body = request.get_json(silent=True) or {}
            username, password = body.get("username"), body.get("password")
            if username is None or password is None:
                self.gen_abort_error(
                    "Missing 'username' or 'password' in JSON body",
                    HTTPStatus.BAD_REQUEST.value,
                )
            return username, password

        header = request.headers.get("Authorization", "")
        parts = header.split(" ", 1)
        if len(parts) != 2 or parts[0] != "Basic":
            self.gen_abort_error(
                "Authorization header must be 'Basic <base64>'",
                HTTPStatus.UNAUTHORIZED.value,
            )
        try:
            decoded = b64decode(parts[1].strip(), validate=True).decode("utf-8")
        except (BinasciiError, ValueError, UnicodeDecodeError):
            self.gen_abort_error(
                "Malformed Basic authorization header", HTTPStatus.BAD_REQUEST.value
            )
        if ":" not in decoded:
            self.gen_abort_error(
                "Basic credentials must be 'username:password'",
                HTTPStatus.BAD_REQUEST.value,
            )
        username, password = decoded.split(":", 1)
        return username, password

    def _build_payload(
        self, subject: Any, token_type: str, ttl_seconds: int
    ) -> dict[str, Any]:
        now = datetime.now(timezone.utc)
        payload: dict[str, Any] = {}
        if token_type == "access" and self._claims_cb is not None:
            extra = self.ensure_sync(self._claims_cb)() or {}
            if not isinstance(extra, dict):
                self.gen_abort_error(
                    "jwt_claims must return a dict",
                    HTTPStatus.INTERNAL_SERVER_ERROR.value,
                )
            payload.update(extra)
        payload.pop("password", None)  # never leak credentials into the token
        payload[self.subject_claim] = subject
        payload.setdefault("iat", now)
        payload.setdefault("exp", now + timedelta(seconds=ttl_seconds))
        payload["type"] = token_type
        payload["jti"] = uuid.uuid4().hex
        return payload

    def _sign(self, payload: dict[str, Any]) -> str:
        config = self._resolve_config()
        key = config["key"]
        algorithm = config["algorithm"]
        if algorithm.upper().startswith(("RS", "ES", "PS")) and self.rsa_encrypt:
            passphrase = config.get("passphrase")
            if passphrase is None:
                self.gen_abort_error(
                    "Missing 'passphrase' for the encrypted private key",
                    HTTPStatus.INTERNAL_SERVER_ERROR.value,
                )
            key = serialization.load_pem_private_key(
                key, password=passphrase, backend=default_backend()
            )
        try:
            return jwt.encode(payload, key, algorithm=algorithm)
        except Exception as exc:  # pragma: no cover - defensive
            self.logger.error("JWT encoding failed: %s", exc)
            self.gen_abort_error(
                "Could not generate the token", HTTPStatus.INTERNAL_SERVER_ERROR.value
            )

    def create_access_token(self, subject: Any) -> str:
        """Sign and return an access token for ``subject``."""
        return self._sign(self._build_payload(subject, "access", self.access_ttl_seconds))

    def create_refresh_token(self, subject: Any) -> str:
        """Sign and return a refresh token for ``subject``."""
        return self._sign(
            self._build_payload(subject, "refresh", self.refresh_ttl_seconds)
        )

    def generate_jwt(
        self,
        func: Optional[Callable] = None,
        roles: Optional[list[str]] = None,
        with_refresh: bool = False,
    ) -> Callable:
        """Decorator that validates credentials and passes a fresh token to the
        view. With ``with_refresh=True`` the view receives ``(access, refresh)``.
        """
        if func is not None and roles is not None:
            raise ValueError("Pass roles as a keyword argument: generate_jwt(roles=[...])")

        def decorator(view: Callable) -> Callable:
            @wraps(view)
            def wrapper(*args: Any, **kwargs: Any):
                if self._bauth_cb is None:
                    self.gen_abort_error(
                        "verify_bauth_credentials is not configured",
                        HTTPStatus.INTERNAL_SERVER_ERROR.value,
                    )
                username, password = self._extract_credentials()
                if not self.ensure_sync(self._bauth_cb)(username, password):
                    self.gen_abort_error(
                        "Invalid credentials", HTTPStatus.UNAUTHORIZED.value
                    )
                self.verify_user_roles(roles, username)
                access = self.create_access_token(username)
                if with_refresh:
                    return self.ensure_sync(view)(
                        access, self.create_refresh_token(username), *args, **kwargs
                    )
                return self.ensure_sync(view)(access, *args, **kwargs)

            return wrapper

        return decorator(func) if func is not None else decorator


class DecJwt(Core):
    """Verify signed tokens and protect routes."""

    def __init__(self, token_as_attr: bool = False) -> None:
        super().__init__()
        # token_as_attr is kept for backward compatibility; the decoded token is
        # always exposed thread-safely via flask.g (see get_current_token()).
        self.token_as_attr = token_as_attr
        self._required_claims_cb: Optional[Callable[[], list[str]]] = None
        self._verify_user_cb: Optional[Callable[[Any], bool]] = None
        self._revoked_cb: Optional[Callable[[dict[str, Any]], bool]] = None

    def get_jwt_claims_to_verify(
        self, func: Callable[[], list[str]]
    ) -> Callable[[], list[str]]:
        """Register the callback returning claim names that must be present."""
        self._required_claims_cb = func
        return func

    def verify_jwt_credentials(
        self, func: Callable[[Any], bool]
    ) -> Callable[[Any], bool]:
        """Register a callback that receives the token subject and returns ``True``
        if the user is still valid (exists / active). No password is involved."""
        self._verify_user_cb = func
        return func

    # Clearer alias for the same behaviour.
    verify_user = verify_jwt_credentials

    def revoked_token_loader(
        self, func: Callable[[dict[str, Any]], bool]
    ) -> Callable[[dict[str, Any]], bool]:
        """Register a callback that receives the decoded token and returns ``True``
        if it is revoked (e.g. its ``jti`` is in a blocklist)."""
        self._revoked_cb = func
        return func

    def _decode(self) -> dict[str, Any]:
        header = request.headers.get("Authorization", "")
        parts = header.split(" ", 1)
        if len(parts) != 2 or parts[0] != "Bearer":
            self.gen_abort_error(
                "Authorization header must be 'Bearer <token>'",
                HTTPStatus.UNAUTHORIZED.value,
            )
        token_str = parts[1].strip()
        config = self._resolve_config()
        keys = config.get("keys") or [config["key"]]
        algorithms = config.get("algorithms") or [config["algorithm"]]
        decode_kwargs: dict[str, Any] = {
            "algorithms": algorithms,
            "leeway": config.get("leeway", 0),
        }
        if "audience" in config:
            decode_kwargs["audience"] = config["audience"]
        if "issuer" in config:
            decode_kwargs["issuer"] = config["issuer"]

        last_signature_error: Optional[Exception] = None
        for key in keys:
            try:
                return jwt.decode(token_str, key, **decode_kwargs)
            except jwt.ExpiredSignatureError:
                self.gen_abort_error("Token has expired", HTTPStatus.UNAUTHORIZED.value)
            except jwt.InvalidAudienceError:
                self.gen_abort_error(
                    "Invalid token audience", HTTPStatus.UNAUTHORIZED.value
                )
            except jwt.InvalidIssuerError:
                self.gen_abort_error(
                    "Invalid token issuer", HTTPStatus.UNAUTHORIZED.value
                )
            except jwt.InvalidSignatureError as exc:
                last_signature_error = exc  # rotation: try the next key
                continue
            except jwt.InvalidTokenError:
                self.gen_abort_error("Invalid token", HTTPStatus.UNAUTHORIZED.value)
        self.logger.info("JWT signature verification failed: %s", last_signature_error)
        self.gen_abort_error("Invalid token", HTTPStatus.UNAUTHORIZED.value)

    def _post_decode_checks(
        self, token: dict[str, Any], roles: Optional[list[str]], expected_type: str
    ) -> Any:
        if self._required_claims_cb is not None:
            for claim in self.ensure_sync(self._required_claims_cb)() or []:
                if claim not in token:
                    self.gen_abort_error(
                        f"Missing required claim '{claim}'",
                        HTTPStatus.UNAUTHORIZED.value,
                    )
        if token.get("type") != expected_type:
            self.gen_abort_error(
                f"A {expected_type} token is required", HTTPStatus.UNAUTHORIZED.value
            )
        if self._revoked_cb is not None and self.ensure_sync(self._revoked_cb)(token):
            self.gen_abort_error("Token has been revoked", HTTPStatus.UNAUTHORIZED.value)
        subject = token.get(self.subject_claim)
        if subject is None:
            self.gen_abort_error(
                "Token is missing the subject claim", HTTPStatus.UNAUTHORIZED.value
            )
        if self._verify_user_cb is not None and not self.ensure_sync(self._verify_user_cb)(
            subject
        ):
            self.gen_abort_error("User is not valid", HTTPStatus.UNAUTHORIZED.value)
        self.verify_user_roles(roles, subject)
        setattr(g, _TOKEN_G_KEY, token)
        return subject

    def login_required(
        self, func: Optional[Callable] = None, roles: Optional[list[str]] = None
    ) -> Callable:
        """Protect a route: verifies signature and standard claims, enforces
        roles, rejects refresh/revoked tokens and exposes the token via
        ``flask.g`` (see :func:`get_current_token`)."""
        if func is not None and roles is not None:
            raise ValueError("Pass roles as a keyword argument: login_required(roles=[...])")

        def decorator(view: Callable) -> Callable:
            @wraps(view)
            def wrapper(*args: Any, **kwargs: Any):
                token = self._decode()
                self._post_decode_checks(token, roles, expected_type="access")
                return self.ensure_sync(view)(*args, **kwargs)

            return wrapper

        return decorator(func) if func is not None else decorator

    def refresh_jwt(self, func: Optional[Callable] = None) -> Callable:
        """Validate a refresh token and pass its subject to the view so it can
        mint a new access token."""

        def decorator(view: Callable) -> Callable:
            @wraps(view)
            def wrapper(*args: Any, **kwargs: Any):
                token = self._decode()
                subject = self._post_decode_checks(token, None, expected_type="refresh")
                return self.ensure_sync(view)(subject, *args, **kwargs)

            return wrapper

        return decorator(func) if func is not None else decorator
