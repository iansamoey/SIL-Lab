"""DELIBERATELY VULNERABLE: lab demonstration for Section 1B Q6. Never enable outside the lab.

This endpoint was written the way AI coding assistants commonly produce code. It is
authenticated, scope-checked, uses parameterised SQL and validates its input, so it
passes a casual review and every generic scanner. Its flaw is a missing business rule:
it never restricts results to the caller's organisation, so any insurer can read every
other insurer's claims for a patient (broken object-level authorisation, OWASP API1).

It is only mounted when LAB_VULNERABLE_ENDPOINTS=true (see main.py).
"""
from uuid import UUID

from fastapi import APIRouter, Depends

from common.auth import Caller, require_scope
from common.db import connect

router = APIRouter()

COLUMNS = "id, patient_id, provider_id, insurer_id, icd10_code, amount_kes, service_date, status"


@router.get("/claims/by-patient/{patient_id}")
def claims_for_patient(patient_id: UUID, caller: Caller = Depends(require_scope("claims:read"))):
    """Return all claims for a patient, newest first."""
    with connect() as conn:
        return conn.execute(
            f"SELECT {COLUMNS} FROM claims WHERE patient_id = %s ORDER BY created_at DESC LIMIT 100",
            (patient_id,),
        ).fetchall()
