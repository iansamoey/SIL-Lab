"""Unit tests for the auth, authorisation and validation logic in both APIs.

The identity provider and database are faked, so these run anywhere
(`pip install -r services/claims/requirements.txt pytest httpx && pytest tests`)
and can run as a CI gate before any container is built.
"""
import base64
import importlib.util
import os
import sys
import time
import uuid
from datetime import date, timedelta
from pathlib import Path

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parent.parent
ISSUER = "http://localhost:8180/realms/sil"
os.environ.update({
    "OIDC_ISSUER": ISSUER,
    "JWKS_URL": "http://jwks.invalid/certs",
    "API_AUDIENCE": "sil-api",
    "DATABASE_URL": "postgresql://unused",
    "PHI_ENC_KEY": base64.urlsafe_b64encode(os.urandom(32)).decode(),
    "PHI_HMAC_KEY": os.urandom(32).hex(),
    "SEED_ON_START": "false",
})
sys.path.insert(0, str(ROOT / "services"))

PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
ATTACKER_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)

import common.auth as auth  # noqa: E402


class _Key:
    key = PRIVATE_KEY.public_key()


@pytest.fixture(autouse=True)
def _trust_test_key(monkeypatch):
    monkeypatch.setattr(auth._jwks, "get_signing_key_from_jwt", lambda token: _Key())


def load(name: str):
    spec = importlib.util.spec_from_file_location(f"{name}_main", ROOT / "services" / name / "main.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


claims = load("claims")
patients = load("patients")


class FakeConn:
    """Records every query; returns whatever `responder(sql, params)` gives back."""
    def __init__(self, responder):
        self.responder, self.calls = responder, []
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def execute(self, sql, params=()):
        self.calls.append((sql, params))
        result = self.responder(sql, params)
        class R:
            def fetchone(_): return result
            def fetchall(_): return result if isinstance(result, list) else [result]
        return R()


def token(client_id="hospital-client", scope="claims:submit claims:read patients:read",
          key=PRIVATE_KEY, alg="RS256", **overrides):
    now = int(time.time())
    claims_ = {"iss": ISSUER, "aud": "sil-api", "azp": client_id, "iat": now, "exp": now + 300,
               "typ": "Bearer", "scope": scope}
    if client_id == "hospital-client":
        claims_["provider_id"] = "PRV-001"
    else:
        claims_["insurer_id"] = "INS-001"
    claims_.update(overrides)
    signing_key = key if alg == "RS256" else "shared-secret-guess"
    return {"Authorization": f"Bearer {jwt.encode(claims_, signing_key, algorithm=alg)}"}


HOSPITAL = token()
INSURER = token("insurer-client", scope="claims:read")
PID = str(uuid.uuid4())


def valid_claim(**overrides):
    body = {"patient_id": PID, "insurer_id": "INS-001", "icd10_code": "I10",
            "amount_kes": "4500.00", "service_date": date.today().isoformat()}
    body.update(overrides)
    return body


@pytest.fixture
def claims_client():
    return TestClient(claims.app)


# ---- Authentication -------------------------------------------------------

@pytest.mark.parametrize("headers", [
    {},
    {"Authorization": "Bearer not-a-jwt"},
    token(key=ATTACKER_KEY),                 # forged signature
    token(alg="HS256"),                      # algorithm confusion attempt
    token(iss="https://evil.example/realms/sil"),
    token(aud="some-other-api"),
    token(exp=int(time.time()) - 120),       # expired beyond leeway
], ids=["none", "garbage", "forged", "hs256", "bad-iss", "bad-aud", "expired"])
def test_bad_tokens_rejected(claims_client, headers):
    assert claims_client.get("/claims", headers=headers).status_code == 401


# ---- Authorisation --------------------------------------------------------

def test_insurer_lacks_submit_scope(claims_client):
    assert claims_client.post("/claims", json=valid_claim(), headers=INSURER).status_code == 403


def test_insurer_reads_are_filtered_to_own_org(claims_client, monkeypatch):
    conn = FakeConn(lambda sql, p: None)
    monkeypatch.setattr(claims, "connect", lambda: conn)
    r = claims_client.get(f"/claims/{uuid.uuid4()}", headers=INSURER)
    assert r.status_code == 404                       # not 403: no existence oracle
    sql, params = conn.calls[0]
    assert "insurer_id = %s" in sql and "INS-001" in params


def test_provider_id_comes_from_token_not_body(claims_client, monkeypatch):
    def responder(sql, p):
        return {"id": uuid.uuid4(), "patient_id": p[0], "provider_id": p[1], "insurer_id": p[2],
                "icd10_code": p[3], "amount_kes": p[4], "service_date": p[5], "status": "SUBMITTED"}
    conn = FakeConn(responder)
    monkeypatch.setattr(claims, "connect", lambda: conn)
    r = claims_client.post("/claims", json=valid_claim(), headers=HOSPITAL)
    assert r.status_code == 201
    assert r.json()["provider_id"] == "PRV-001"
    assert conn.calls[0][1][-1] == "hospital-client"  # submitted_by audit field


# ---- Input validation -----------------------------------------------------

@pytest.mark.parametrize("body", [
    valid_claim(provider_id="PRV-999"),               # mass assignment
    valid_claim(amount_kes="-5"),
    valid_claim(amount_kes="99999999999"),
    valid_claim(icd10_code="DROP TABLE"),
    valid_claim(insurer_id="INS-1; --"),
    valid_claim(patient_id="not-a-uuid"),
], ids=["extra-field", "negative", "too-large", "bad-icd10", "bad-insurer", "bad-uuid"])
def test_invalid_claims_rejected(claims_client, body):
    assert claims_client.post("/claims", json=body, headers=HOSPITAL).status_code == 422


def test_future_service_date_rejected(claims_client):
    future = (date.today() + timedelta(days=3)).isoformat()
    assert claims_client.post("/claims", json=valid_claim(service_date=future),
                              headers=HOSPITAL).status_code == 422


def test_docs_not_exposed(claims_client):
    for path in ("/docs", "/redoc", "/openapi.json"):
        assert claims_client.get(path).status_code == 404


# ---- Patient API: PHI handling --------------------------------------------

def test_patient_search_uses_blind_index_and_masks_output(monkeypatch):
    f = patients.FERNET
    row = {"id": uuid.uuid4(), "given_name": "Amani", "family_name": "Otieno",
           "date_of_birth": date(1985, 3, 14),
           "national_id_enc": f.encrypt(b"23456789").decode(),
           "phone_enc": f.encrypt(b"+254700000001").decode()}
    conn = FakeConn(lambda sql, p: row)
    monkeypatch.setattr(patients, "connect", lambda: conn)
    r = TestClient(patients.app).post("/patients/search", json={"national_id": "23456789"},
                                      headers=HOSPITAL)
    assert r.status_code == 200
    body = r.json()
    assert body["national_id_masked"] == "*****789"
    assert body["phone_masked"].endswith("001") and "254700" not in body["phone_masked"]
    sql, params = conn.calls[0]
    assert "23456789" not in str(params)              # plaintext ID never sent to the DB
    assert params[0] == patients.blind_index("23456789")


def test_patient_search_rejects_malformed_id():
    r = TestClient(patients.app).post("/patients/search", json={"national_id": "1' OR '1'='1"},
                                      headers=HOSPITAL)
    assert r.status_code == 422


def test_insurer_cannot_search_patients():
    r = TestClient(patients.app).post("/patients/search", json={"national_id": "23456789"},
                                      headers=INSURER)
    assert r.status_code == 403
