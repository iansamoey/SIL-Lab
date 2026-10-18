#!/usr/bin/env python3
"""Section 1B Q6 demo: SAST, DAST and a cross-tenant authorisation test against the same
deliberately planted AI-generated flaw (GET /api/claims/by-patient/{id}, which forgets the
organisation filter). Run it with `make demo-dast`, which enables that endpoint first and
disables it afterwards.

Set MODE=baseline for the quick passive scan used on pull requests (~1-2 min);
the default is the full active scan used nightly (several minutes).
"""
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ENV = dict(l.split("=", 1) for l in (ROOT / ".env").read_text().splitlines()
           if "=" in l and not l.startswith("#"))
GW, KC = "http://localhost:8080", "http://localhost:8180/realms/sil/protocol/openid-connect/token"
SEMGREP = os.environ.get("SEMGREP_IMAGE", "semgrep/semgrep:1.178.0")
ZAP = os.environ.get("ZAP_IMAGE", "zaproxy/zap-stable:2.17.0")
MODE = os.environ.get("MODE", "full")
WORK = ROOT / "security/dast/work"
results = {"pass": 0, "fail": 0}


def check(name, ok, detail=""):
    results["pass" if ok else "fail"] += 1
    print(f"  {'PASS' if ok else 'FAIL'}  {name:<64} {detail}")


def token(client, secret):
    data = urllib.parse.urlencode({"grant_type": "client_credentials", "client_id": client,
                                   "client_secret": secret}).encode()
    with urllib.request.urlopen(KC, data=data, timeout=10) as r:
        return json.load(r)["access_token"]


def call(method, path, tok, body=None):
    req = urllib.request.Request(GW + path, method=method,
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Authorization": f"Bearer {tok}", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.load(e)
        except ValueError:
            return e.code, None


def run(cmd, **kw):
    return subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, **kw)


hospital = token("hospital-client", ENV["HOSPITAL_CLIENT_SECRET"])
insurer = token("insurer-client", ENV["INSURER_CLIENT_SECRET"])

print("== Setup: waiting for the claims API, creating test data")
for _ in range(30):
    if call("GET", "/api/claims", hospital)[0] == 200:
        break
    time.sleep(3)
status, patient = call("POST", "/api/patients/search", hospital, {"national_id": "34567890"})
pid = patient["id"]
today = time.strftime("%Y-%m-%d")
_, own = call("POST", "/api/claims", hospital, {"patient_id": pid, "insurer_id": "INS-001",
              "icd10_code": "I10", "amount_kes": "3000.00", "service_date": today})
_, other = call("POST", "/api/claims", hospital, {"patient_id": pid, "insurer_id": "INS-002",
                "icd10_code": "E11.9", "amount_kes": "8200.00", "service_date": today})
mounted = call("GET", f"/api/claims/by-patient/{pid}", hospital)[0] == 200
check("AI-generated endpoint is mounted for the demo", mounted,
      "" if mounted else "run via `make demo-dast`, which enables it")
if not mounted:
    sys.exit(1)

# ---------------------------------------------------------------------------
print("\n== 1. SAST: Semgrep with SIL custom rules")
t = run(["docker", "run", "--rm", "-v", f"{ROOT}:/src:ro", SEMGREP,
         "semgrep", "--test", "--metrics=off", "/src/security/semgrep"])
check("Custom rules pass their own test cases", t.returncode == 0)
s = run(["docker", "run", "--rm", "-v", f"{ROOT}:/src:ro", SEMGREP, "semgrep", "scan", "--metrics=off",
         "--quiet", "--json", "--config", "/src/security/semgrep/sil-rules.yaml", "/src/services"])
findings = json.loads(s.stdout or '{"results": []}')["results"]
for f in findings:
    print(f"        {f['check_id'].split('.')[-1]}  {f['path'].replace('/src/', '')}:{f['start']['line']}")
check("Semgrep flags the missing organisation filter",
      any("missing-org-filter" in f["check_id"] and "ai_generated.py" in f["path"] for f in findings))
check("No other findings (no false positives in the codebase)", len(findings) == 1, f"{len(findings)} finding(s)")

# ---------------------------------------------------------------------------
print(f"\n== 2. DAST: OWASP ZAP {'baseline (passive)' if MODE == 'baseline' else 'full active'} API scan")
WORK.mkdir(parents=True, exist_ok=True)
WORK.chmod(0o777)
spec = (ROOT / "security/dast/openapi.yaml.tmpl").read_text()
(WORK / "openapi.yaml").write_text(spec.replace("{{PATIENT_ID}}", pid).replace("{{CLAIM_ID}}", own["id"]))
for old in WORK.glob("zap-report.*"):
    old.unlink()
scanner = token("dast-scanner", ENV["DAST_SCANNER_CLIENT_SECRET"])
cmd = ["docker", "run", "--rm", "--network", "sil-gateway-lab_edge",
       "-e", f"ZAP_AUTH_HEADER_VALUE=Bearer {scanner}", "-v", f"{WORK}:/zap/wrk:rw", ZAP,
       "zap-api-scan.py", "-t", "/zap/wrk/openapi.yaml", "-f", "openapi",
       "-J", "zap-report.json", "-r", "zap-report.html", "-w", "zap-report.md", "-I"]
if MODE == "baseline":
    cmd.append("-S")                       # safe mode: passive checks only, no attack traffic
print(f"        scanning as dast-scanner (read-only identity); this can take several minutes...")
started = time.time()
z = run(cmd)
report_file = WORK / "zap-report.json"
check("ZAP scan completed and wrote a report", report_file.exists(),
      f"{round((time.time() - started) / 60, 1)} min" if report_file.exists() else (z.stderr or z.stdout)[-300:])
alerts = []
if report_file.exists():
    for site in json.loads(report_file.read_text()).get("site", []):
        alerts += site.get("alerts", [])
order = {"High": 0, "Medium": 1, "Low": 2, "Informational": 3}
alerts.sort(key=lambda a: order.get(a["riskdesc"].split()[0], 9))
print(f"        {'Risk (confidence)':<26} {'Alert':<52} Instances")
for a in alerts:
    print(f"        {a['riskdesc']:<26} {a['name'][:50]:<52} {a['count']}")
if not alerts:
    print("        (no alerts)")
hits = [a for a in alerts if any("by-patient" in i.get("uri", "") for i in a.get("instances", []))
        and a["riskdesc"].split()[0] in ("High", "Medium")]
print(f"        High/Medium alerts on the by-patient endpoint: {len(hits)}")
print("        -> ZAP sees every response as legitimate: it scans as ONE identity, so it cannot")
print("           know that a different organisation should not see these claims.")

# ---------------------------------------------------------------------------
print("\n== 3. Cross-tenant authorisation test (DAST adapted for logic flaws)")
status, _ = call("GET", f"/api/claims/{other['id']}", insurer)
check("Correct endpoint: INS-001 cannot read INS-002's claim", status == 404, f"HTTP {status}")
status, rows = call("GET", f"/api/claims/by-patient/{pid}", insurer)
leaked = [r for r in (rows or []) if r.get("insurer_id") != "INS-001"]
check("Two-tenant test detects the AI-generated leak", bool(leaked),
      f"INS-001 received {len(leaked)} claim(s) belonging to {sorted({r['insurer_id'] for r in leaked})}")

print("\n== What caught the AI-generated flaw")
print(f"        Semgrep custom rule        {'YES' if any('missing-org-filter' in f['check_id'] for f in findings) else 'no'}  (before merge, in seconds)")
print(f"        ZAP generic scan           {'YES' if hits else 'no'}   (finds injection, headers, misconfig, not business logic)")
print(f"        Two-tenant authz test      {'YES' if leaked else 'no'}  (at runtime, every deploy)")
print(f"\n        Full ZAP report: {WORK / 'zap-report.html'}")
print(f"\nResult: {results['pass']} passed, {results['fail']} failed")
sys.exit(1 if results["fail"] else 0)
