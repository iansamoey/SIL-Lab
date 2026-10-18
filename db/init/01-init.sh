#!/bin/bash
# Creates schema and least-privilege roles. Each service gets its own DB user
# with only the rights it needs; neither can touch the other's table.
set -euo pipefail

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
  REVOKE ALL ON SCHEMA public FROM PUBLIC;

  CREATE ROLE claims_svc  LOGIN PASSWORD '${CLAIMS_DB_PASSWORD}';
  CREATE ROLE patient_svc LOGIN PASSWORD '${PATIENT_DB_PASSWORD}';
  GRANT USAGE ON SCHEMA public TO claims_svc, patient_svc;

  -- Direct identifiers are encrypted at the application layer (Fernet).
  -- national_id_hmac is a keyed blind index, so we can look up by ID
  -- without storing or querying the plaintext.
  CREATE TABLE patients (
    id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    given_name        text NOT NULL,
    family_name       text NOT NULL,
    date_of_birth     date NOT NULL,
    national_id_enc   text NOT NULL,
    national_id_hmac  text NOT NULL UNIQUE,
    phone_enc         text,
    created_at        timestamptz NOT NULL DEFAULT now()
  );

  CREATE TABLE claims (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    patient_id    uuid NOT NULL REFERENCES patients(id),
    provider_id   text NOT NULL,           -- from the caller's token, never the request body
    insurer_id    text NOT NULL,
    icd10_code    text NOT NULL,
    amount_kes    numeric(12,2) NOT NULL CHECK (amount_kes > 0),
    service_date  date NOT NULL,
    status        text NOT NULL DEFAULT 'SUBMITTED',
    submitted_by  text NOT NULL,           -- OAuth client id, for audit
    created_at    timestamptz NOT NULL DEFAULT now()
  );
  CREATE INDEX claims_provider_idx ON claims (provider_id);
  CREATE INDEX claims_insurer_idx  ON claims (insurer_id);

  -- No UPDATE or DELETE for either service: claims are append-only.
  GRANT SELECT, INSERT ON claims   TO claims_svc;
  GRANT SELECT, INSERT ON patients TO patient_svc;   -- INSERT only needed for lab seeding
EOSQL
