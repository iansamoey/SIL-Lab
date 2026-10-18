# Test cases for sil-rules.yaml. A "ruleid" annotation marks a line that must be
# flagged; an "ok" annotation marks one that must not be. Run: semgrep --test security/semgrep/
from fastapi import Depends


# ---- sil-claims-query-missing-org-filter --------------------------------------

def claims_for_patient(patient_id, caller=Depends(require_scope("claims:read"))):
    with connect() as conn:
        # ruleid: sil-claims-query-missing-org-filter
        return conn.execute(f"SELECT {COLUMNS} FROM claims WHERE patient_id = %s", (patient_id,)).fetchall()


def get_claim(claim_id, caller=Depends(require_scope("claims:read"))):
    predicate, value = org_filter(caller)
    with connect() as conn:
        # ok: sil-claims-query-missing-org-filter
        return conn.execute(f"SELECT {COLUMNS} FROM claims WHERE id = %s AND {predicate}", (claim_id, value)).fetchone()


def submit(claim, caller):
    with connect() as conn:
        # ok: sil-claims-query-missing-org-filter
        conn.execute("INSERT INTO claims (patient_id) VALUES (%s) RETURNING id", (claim.patient_id,))


# ---- sil-route-missing-auth ---------------------------------------------------

# ruleid: sil-route-missing-auth
@app.get("/claims/export")
def export_claims(limit: int = 100):
    return []


# ok: sil-route-missing-auth
@app.get("/claims/{claim_id}")
def read_claim(claim_id, caller: Caller = Depends(require_scope("claims:read"))):
    return {}


# ok: sil-route-missing-auth
@router.post("/claims")
def create(body, caller=Depends(require_scope("claims:submit"))):
    return {}


# ok: sil-route-missing-auth
@app.get("/health", include_in_schema=False)
def health():
    return {"status": "ok"}


# ---- sil-org-identity-from-request --------------------------------------------

def submit_trusting_body(claim, caller):
    with connect() as conn:
        conn.execute(
            "INSERT INTO claims (patient_id, provider_id) VALUES (%s, %s)",
            # ruleid: sil-org-identity-from-request
            (claim.patient_id, claim.provider_id),
        )


def submit_correctly(claim, caller):
    with connect() as conn:
        conn.execute(
            "INSERT INTO claims (patient_id, provider_id) VALUES (%s, %s)",
            # ok: sil-org-identity-from-request
            (claim.patient_id, caller.provider_id),
        )


def submit_with_destination_insurer(claim, caller):
    with connect() as conn:
        conn.execute(
            "INSERT INTO claims (patient_id, provider_id, insurer_id) VALUES (%s, %s, %s)",
            # ok: sil-org-identity-from-request
            (claim.patient_id, caller.provider_id, claim.insurer_id),
        )
