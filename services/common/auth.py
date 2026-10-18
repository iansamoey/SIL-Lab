"""Token verification shared by both services.

Kong already verifies the token signature, but the services verify it again.
This is defence in depth: if anyone ever reaches a service without going
through the gateway (misconfigured network, compromised pod), an unsigned or
forged token still gets nothing. Authorisation (scopes, which organisation the
caller belongs to) is decided here, close to the data.
"""
import logging
import os
from dataclasses import dataclass

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt import PyJWKClient

log = logging.getLogger("auth")

ISSUER = os.environ["OIDC_ISSUER"]
AUDIENCE = os.environ.get("API_AUDIENCE", "sil-api")
_jwks = PyJWKClient(os.environ["JWKS_URL"], cache_keys=True, lifespan=300)
_bearer = HTTPBearer(auto_error=False)


@dataclass(frozen=True)
class Caller:
    client_id: str
    scopes: frozenset
    provider_id: str | None
    insurer_id: str | None


def _unauthorized() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="invalid or missing token",
        headers={"WWW-Authenticate": "Bearer"},
    )


def get_caller(creds: HTTPAuthorizationCredentials | None = Depends(_bearer)) -> Caller:
    if creds is None:
        raise _unauthorized()
    token = creds.credentials
    try:
        key = _jwks.get_signing_key_from_jwt(token).key
        claims = jwt.decode(
            token,
            key,
            algorithms=["RS256"],          # pinned: blocks alg=none / HS256 confusion attacks
            audience=AUDIENCE,
            issuer=ISSUER,
            options={"require": ["exp", "iat", "iss", "aud", "azp"]},
            leeway=30,
        )
    except jwt.PyJWTError as exc:
        log.warning("token rejected: %s", type(exc).__name__)  # never log the token itself
        raise _unauthorized()
    if claims.get("typ", "Bearer") != "Bearer":
        raise _unauthorized()
    return Caller(
        client_id=claims["azp"],
        scopes=frozenset(claims.get("scope", "").split()),
        provider_id=claims.get("provider_id"),
        insurer_id=claims.get("insurer_id"),
    )


def require_scope(scope: str):
    def dependency(caller: Caller = Depends(get_caller)) -> Caller:
        if scope not in caller.scopes:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="insufficient scope")
        return caller
    return dependency
