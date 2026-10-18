"""Sample API 1: claims submission and retrieval (modelled on an eClaims flow).

Key controls:
  * provider_id comes from the verified token, never from the request body
  * every read is filtered by the caller's organisation (prevents BOLA/IDOR)
  * strict input schema; unknown fields are rejected (prevents mass assignment)
  * parameterised SQL only
"""
import os
from datetime import date
from decimal import Decimal
from uuid import UUID

import psycopg
from fastapi import Depends, FastAPI, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field

from common.auth import Caller, require_scope
from common.db import connect

# No public docs/OpenAPI: don't hand attackers a map of the API.
app = FastAPI(title="SIL Claims API (lab)", docs_url=None, redoc_url=None, openapi_url=None)

ICD10_PATTERN = r"^[A-TV-Z][0-9][0-9AB](\.[0-9A-TV-Z]{1,4})?$"


class ClaimIn(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    patient_id: UUID
    insurer_id: str = Field(pattern=r"^INS-\d{3}$")
    icd10_code: str = Field(pattern=ICD10_PATTERN)
    amount_kes: Decimal = Field(gt=0, le=Decimal("10000000"), max_digits=12, decimal_places=2)
    service_date: date


class ClaimOut(BaseModel):
    id: UUID
    patient_id: UUID
    provider_id: str
    insurer_id: str
    icd10_code: str
    amount_kes: Decimal
    service_date: date
    status: str


COLUMNS = "id, patient_id, provider_id, insurer_id, icd10_code, amount_kes, service_date, status"


def org_filter(caller: Caller) -> tuple[str, str]:
    """Return a fixed SQL predicate plus its parameter for the caller's organisation.

    The predicate strings are constants chosen here, never built from input.
    """
    if caller.provider_id:
        return "provider_id = %s", caller.provider_id
    if caller.insurer_id:
        return "insurer_id = %s", caller.insurer_id
    raise HTTPException(status.HTTP_403_FORBIDDEN, "caller is not bound to an organisation")


@app.get("/health", include_in_schema=False)
def health():
    return {"status": "ok"}


@app.post("/claims", status_code=status.HTTP_201_CREATED, response_model=ClaimOut)
def submit_claim(claim: ClaimIn, caller: Caller = Depends(require_scope("claims:submit"))):
    if not caller.provider_id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "only providers can submit claims")
    if claim.service_date > date.today():
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "service_date cannot be in the future")
    try:
        with connect() as conn:
            row = conn.execute(
                f"""INSERT INTO claims (patient_id, provider_id, insurer_id, icd10_code,
                                        amount_kes, service_date, submitted_by)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    RETURNING {COLUMNS}""",
                (claim.patient_id, caller.provider_id, claim.insurer_id, claim.icd10_code,
                 claim.amount_kes, claim.service_date, caller.client_id),
            ).fetchone()
    except psycopg.errors.ForeignKeyViolation:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "unknown patient_id")
    return row


@app.get("/claims", response_model=list[ClaimOut])
def list_claims(
    caller: Caller = Depends(require_scope("claims:read")),
    limit: int = Query(20, ge=1, le=100),
):
    predicate, value = org_filter(caller)
    with connect() as conn:
        return conn.execute(
            f"SELECT {COLUMNS} FROM claims WHERE {predicate} ORDER BY created_at DESC LIMIT %s",
            (value, limit),
        ).fetchall()


@app.get("/claims/{claim_id}", response_model=ClaimOut)
def get_claim(claim_id: UUID, caller: Caller = Depends(require_scope("claims:read"))):
    predicate, value = org_filter(caller)
    with connect() as conn:
        row = conn.execute(
            f"SELECT {COLUMNS} FROM claims WHERE id = %s AND {predicate}",
            (claim_id, value),
        ).fetchone()
    if row is None:
        # 404, not 403: don't confirm that a claim exists to someone who can't see it.
        raise HTTPException(status.HTTP_404_NOT_FOUND, "claim not found")
    return row


# Lab only: mount the deliberately vulnerable AI-generated endpoint for the Q6 demo.
if os.environ.get("LAB_VULNERABLE_ENDPOINTS") == "true":
    from ai_generated import router as _ai_generated_router
    app.include_router(_ai_generated_router)
