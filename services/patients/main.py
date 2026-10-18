"""Sample API 2: patient lookup.

Key controls:
  * national ID and phone are encrypted at rest at the application layer (Fernet)
  * lookup uses a keyed HMAC "blind index", so plaintext IDs are never queried or stored
  * search is POST with the ID in the body: IDs never appear in URLs or access logs
  * responses return masked identifiers only (data minimisation)
"""
import hashlib
import hmac
import os
from contextlib import asynccontextmanager
from datetime import date
from uuid import UUID

from cryptography.fernet import Fernet
from fastapi import Depends, FastAPI, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field

from common.auth import Caller, require_scope
from common.db import connect

FERNET = Fernet(os.environ["PHI_ENC_KEY"].encode())
HMAC_KEY = bytes.fromhex(os.environ["PHI_HMAC_KEY"])

# Entirely synthetic test data. Never seed a lab with real patient records.
SEED_PATIENTS = [
    ("Amani", "Otieno", date(1985, 3, 14), "23456789", "+254700000001"),
    ("Wanjiru", "Kamau", date(1992, 11, 2), "34567890", "+254700000002"),
    ("Baraka", "Mwangi", date(1978, 6, 21), "45678901", "+254700000003"),
]


def blind_index(value: str) -> str:
    return hmac.new(HMAC_KEY, value.strip().encode(), hashlib.sha256).hexdigest()


def mask(value: str, visible: int = 3) -> str:
    return "*" * max(len(value) - visible, 0) + value[-visible:]


def seed() -> None:
    with connect() as conn:
        for given, family, dob, nid, phone in SEED_PATIENTS:
            conn.execute(
                """INSERT INTO patients (given_name, family_name, date_of_birth,
                                         national_id_enc, national_id_hmac, phone_enc)
                   VALUES (%s, %s, %s, %s, %s, %s)
                   ON CONFLICT (national_id_hmac) DO NOTHING""",
                (given, family, dob, FERNET.encrypt(nid.encode()).decode(),
                 blind_index(nid), FERNET.encrypt(phone.encode()).decode()),
            )


@asynccontextmanager
async def lifespan(_app: FastAPI):
    if os.environ.get("SEED_ON_START", "true") == "true":
        seed()
    yield


app = FastAPI(title="SIL Patient API (lab)", docs_url=None, redoc_url=None,
              openapi_url=None, lifespan=lifespan)


class SearchIn(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    national_id: str = Field(pattern=r"^\d{7,9}$")


class PatientOut(BaseModel):
    id: UUID
    given_name: str
    family_name: str
    date_of_birth: date
    national_id_masked: str
    phone_masked: str | None


def to_out(row: dict) -> PatientOut:
    nid = FERNET.decrypt(row["national_id_enc"].encode()).decode()
    phone = FERNET.decrypt(row["phone_enc"].encode()).decode() if row["phone_enc"] else None
    return PatientOut(
        id=row["id"], given_name=row["given_name"], family_name=row["family_name"],
        date_of_birth=row["date_of_birth"], national_id_masked=mask(nid),
        phone_masked=mask(phone) if phone else None,
    )


COLUMNS = "id, given_name, family_name, date_of_birth, national_id_enc, phone_enc"


@app.get("/health", include_in_schema=False)
def health():
    return {"status": "ok"}


@app.post("/patients/search", response_model=PatientOut)
def search(body: SearchIn, _caller: Caller = Depends(require_scope("patients:read"))):
    with connect() as conn:
        row = conn.execute(
            f"SELECT {COLUMNS} FROM patients WHERE national_id_hmac = %s",
            (blind_index(body.national_id),),
        ).fetchone()
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "patient not found")
    return to_out(row)


@app.get("/patients/{patient_id}", response_model=PatientOut)
def get_patient(patient_id: UUID, _caller: Caller = Depends(require_scope("patients:read"))):
    with connect() as conn:
        row = conn.execute(f"SELECT {COLUMNS} FROM patients WHERE id = %s", (patient_id,)).fetchone()
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "patient not found")
    return to_out(row)
