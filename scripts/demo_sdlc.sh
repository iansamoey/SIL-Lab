#!/usr/bin/env bash
# Section 1B Q2 demo: pre-commit secret scanning and the dependency gate, in a
# throwaway git repo so your lab's history is never touched.
set -uo pipefail
cd "$(dirname "$0")/.."
ROOT="$PWD"; PASS=0; FAIL=0
check() {
  if [[ "$2" == "$3" ]]; then printf '  PASS  %s\n' "$1"; PASS=$((PASS+1))
  else printf '  FAIL  %s (expected %s, got %s)\n' "$1" "$2" "$3"; FAIL=$((FAIL+1)); fi
}
for tool in git gitleaks pre-commit python3 docker; do
  command -v "$tool" >/dev/null || { echo "missing $tool: run 'make install-tools' first"; exit 1; }
done

work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT
mkdir -p "$work/scripts" "$work/security/deps"
cp .gitleaks.toml .pre-commit-config.yaml "$work/"
cp scripts/check_dependencies.py "$work/scripts/"; cp security/deps/approved.txt "$work/security/deps/"
cd "$work"
git init -q && git config user.email demo@example.com && git config user.name "Demo Developer"
git add . && git commit -qm "baseline" --no-verify
pre-commit install >/dev/null

echo "== 1. A developer hardcodes credentials while debugging with an AI assistant"
# Built at runtime so this script itself contains no secret for scanners to flag.
PW="Xk9vQ2mL""p7RtW4zN"
printf 'import psycopg\n# debugging with Copilot: why does this connection fail?\nconn = psycopg.connect("%s://%s:%s@%s")\n' \
  postgresql claims_svc "$PW" "db.prod.internal:5432/sil" > app.py
git add app.py
echo "  \$ git commit -m 'debug db connection'"
git commit -m "debug db connection" > hook.log 2>&1; rc=$?
sed -n 's/^\(RuleID\|Secret\|File\|Line\):/    &/p' hook.log | head -4
check "Pre-commit hook blocks the commit" 1 "$rc"
check "Secret is redacted in the hook output" 0 "$(grep -c "$PW" hook.log)"

echo; echo "== 2. The developer bypasses the hook with --no-verify"
git commit -qm "debug db connection" --no-verify
gitleaks git --no-banner --redact --config .gitleaks.toml . > ci.log 2>&1; rc=$?
check "CI's full-history scan still catches it" 1 "$rc"
echo "    (the secret is now in git history: rotating the credential is mandatory, deleting the file is not enough)"

echo; echo "== 3. An AI assistant suggests dependencies for a new feature"
cp "$ROOT/tests/fixtures/requirements-ai-suggested.txt" requirements.txt
git add requirements.txt
git commit -m "add payment deps" > deps.log 2>&1; rc=$?
grep -E '^(FAIL|WARN)' deps.log | sed 's/   \[.*//; s/^/    /'
check "Dependency gate blocks hallucinated and typosquatted packages" 1 "$rc"

echo; echo "== 4. OSV-Scanner checks the real packages for known vulnerabilities"
docker run --rm -v "$ROOT/tests/fixtures:/src:ro" ghcr.io/google/osv-scanner:v2.6.0 \
  scan source -L requirements.txt:/src/requirements-ai-suggested.txt > osv.log 2>&1; rc=$?
grep -E 'GHSA|PYSEC|requests' osv.log | head -6 || tail -3 osv.log | sed 's/^/    /'
ids=$(grep -oE "(GHSA|PYSEC)-[A-Za-z0-9-]+" osv.log | sort -u | wc -l)
check "OSV-Scanner reports real vulnerability IDs (found $ids)" yes "$([[ $rc -eq 1 && $ids -gt 0 ]] && echo yes || echo no)"

echo; echo "Result: $PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
