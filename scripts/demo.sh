#!/usr/bin/env bash
# Runs a series of requests through the WAF and gateway and checks that each
# security control behaves as expected. Output is suitable for screenshots.
set -uo pipefail
cd "$(dirname "$0")/.."
set -a; source .env; set +a

GW="${GW:-http://localhost:8080}"
KC="${KC:-http://localhost:8180}"
BODY="$(mktemp)"; trap 'rm -f "$BODY"' EXIT
PASS=0; FAIL=0

token() {
  curl -s -X POST "$KC/realms/sil/protocol/openid-connect/token" \
    -d grant_type=client_credentials -d client_id="$1" -d client_secret="$2" \
  | python3 -c 'import sys,json; print(json.load(sys.stdin)["access_token"])'
}
req()   { curl -s -o "$BODY" -w '%{http_code}' "$@"; }
field() { python3 -c "import json,sys; print(json.load(open('$BODY'))['$1'])"; }
check() {
  if [[ "$2" == "$3" ]]; then printf '  PASS  %-58s HTTP %s\n' "$1" "$3"; PASS=$((PASS+1))
  else printf '  FAIL  %-58s expected %s, got %s\n' "$1" "$2" "$3"; FAIL=$((FAIL+1)); fi
}

echo "== Getting tokens from Keycloak (OAuth2 client credentials)"
HT="$(token hospital-client "$HOSPITAL_CLIENT_SECRET")" || { echo "token request failed"; exit 1; }
IT="$(token insurer-client "$INSURER_CLIENT_SECRET")"  || { echo "token request failed"; exit 1; }
H=(-H "Authorization: Bearer $HT" -H "Content-Type: application/json")
I=(-H "Authorization: Bearer $IT" -H "Content-Type: application/json")
TODAY="$(date +%F)"

echo; echo "== Authentication (Kong jwt plugin)"
check "No token is rejected"                         401 "$(req "$GW/api/claims")"
check "Token with forged signature is rejected"      401 "$(req -H "Authorization: Bearer ${HT%.*}.Zm9yZ2Vk" "$GW/api/claims")"

echo; echo "== Happy path"
check "Hospital looks up patient (ID in POST body)"  200 "$(req "${H[@]}" -d '{"national_id":"23456789"}' "$GW/api/patients/search")"
PID="$(field id)"; echo "        patient $PID, national ID returned as $(field national_id_masked)"
check "Hospital submits claim to INS-001"            201 "$(req "${H[@]}" -d "{\"patient_id\":\"$PID\",\"insurer_id\":\"INS-001\",\"icd10_code\":\"I10\",\"amount_kes\":4500.00,\"service_date\":\"$TODAY\"}" "$GW/api/claims")"
CID="$(field id)"
check "Insurer INS-001 reads that claim"             200 "$(req "${I[@]}" "$GW/api/claims/$CID")"

echo; echo "== Authorisation"
check "Insurer cannot submit claims (gateway ACL)"   403 "$(req "${I[@]}" -d '{}' "$GW/api/claims")"
check "Insurer cannot query patients (gateway ACL)"  403 "$(req "${I[@]}" -d '{"national_id":"23456789"}' "$GW/api/patients/search")"
req "${H[@]}" -d "{\"patient_id\":\"$PID\",\"insurer_id\":\"INS-002\",\"icd10_code\":\"E11.9\",\"amount_kes\":1200.00,\"service_date\":\"$TODAY\"}" "$GW/api/claims" >/dev/null
OTHER="$(field id)"
check "Insurer INS-001 cannot read INS-002's claim (BOLA)" 404 "$(req "${I[@]}" "$GW/api/claims/$OTHER")"

echo; echo "== Input validation (API layer)"
check "Extra field provider_id rejected (mass assignment)" 422 "$(req "${H[@]}" -d "{\"patient_id\":\"$PID\",\"insurer_id\":\"INS-001\",\"icd10_code\":\"I10\",\"amount_kes\":10,\"service_date\":\"$TODAY\",\"provider_id\":\"PRV-999\"}" "$GW/api/claims")"
check "Negative amount rejected"                     422 "$(req "${H[@]}" -d "{\"patient_id\":\"$PID\",\"insurer_id\":\"INS-001\",\"icd10_code\":\"I10\",\"amount_kes\":-5,\"service_date\":\"$TODAY\"}" "$GW/api/claims")"

echo; echo "== WAF (ModSecurity + OWASP CRS + SIL custom rules)"
check "SQL injection in JSON body blocked"           403 "$(req "${H[@]}" -d "{\"national_id\":\"1' OR '1'='1\"}" "$GW/api/patients/search")"
check "XSS in query string blocked"                  403 "$(req "${H[@]}" "$GW/api/claims?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E")"
check "National ID in URL blocked (custom rule 10001)" 403 "$(req "${H[@]}" "$GW/api/patients?national_id=23456789")"
check "Internal path /docs hidden (custom rule 10002)" 404 "$(req "$GW/api/claims/docs")"

echo; echo "== Gateway limits"
BIG="$(python3 -c 'print("{\"national_id\":\"" + "1"*100000 + "\"}")')"
check "Oversized body rejected"                      413 "$(req "${H[@]}" -d "$BIG" "$GW/api/patients/search")"
LAST=""
for _ in $(seq 1 70); do LAST="$(req "${I[@]}" "$GW/api/claims")"; [[ "$LAST" == 429 ]] && break; done
check "Rate limit enforced per client (60/min)"      429 "$LAST"

echo; echo "== Network isolation"
check "Kong is not reachable from the host"          000 "$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 http://localhost:8000/ || true)"

echo; echo "Result: $PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
