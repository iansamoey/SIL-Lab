"""The planted AI-generated endpoint: off by default, and genuinely flawed when on."""
import importlib.util
import os
import sys
import time
import uuid
from pathlib import Path

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parent.parent
ISSUER = "http://localhost:8180/realms/sil"
os.environ.update({"OIDC_ISSUER": ISSUER, "JWKS_URL": "http://jwks.invalid/certs",
                   "API_AUDIENCE": "sil-api", "DATABASE_URL": "postgresql://unused"})
sys.path.insert(0, str(ROOT / "services"))
sys.path.insert(0, str(ROOT / "services" / "claims"))
import common.auth as auth  # noqa: E402

KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(autouse=True)
def _trust_key(monkeypatch):
    monkeypatch.setattr(auth._jwks, "get_signing_key_from_jwt",
                        lambda t: type("K", (), {"key": KEY.public_key()})())


def load_claims(flag: str):
    os.environ["LAB_VULNERABLE_ENDPOINTS"] = flag
    spec = importlib.util.spec_from_file_location(f"claims_{flag}", ROOT / "services/claims/main.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    os.environ.pop("LAB_VULNERABLE_ENDPOINTS")
    return mod


def insurer():
    now = int(time.time())
    return {"Authorization": "Bearer " + jwt.encode(
        {"iss": ISSUER, "aud": "sil-api", "azp": "insurer-client", "iat": now, "exp": now + 300,
         "scope": "claims:read", "insurer_id": "INS-001"}, KEY, algorithm="RS256")}


def test_vulnerable_endpoint_is_off_by_default():
    app = load_claims("false").app
    r = TestClient(app).get(f"/claims/by-patient/{uuid.uuid4()}", headers=insurer())
    assert r.status_code == 404


def test_vulnerable_endpoint_query_has_no_org_filter(monkeypatch):
    import ai_generated
    calls = []

    class Conn:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def execute(self, sql, params):
            calls.append((sql, params))
            return type("R", (), {"fetchall": lambda s: []})()

    monkeypatch.setattr(ai_generated, "connect", lambda: Conn())
    app = load_claims("true").app
    assert TestClient(app).get(f"/claims/by-patient/{uuid.uuid4()}", headers=insurer()).status_code == 200
    sql, params = calls[0]
    assert "insurer_id" not in sql.split("WHERE", 1)[1]   # the flaw: no organisation predicate
    assert "INS-001" not in params
