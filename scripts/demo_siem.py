#!/usr/bin/env python3
"""Section 1B Q3 demo: Wazuh detecting ransomware, Shadow AI, gateway and WAF attacks
and AI-policy violations, using the log sources onboarded in siem/config/ossec.conf.

  Part 1  Rule unit tests through Wazuh's own wazuh-logtest (decoding + rule matching)
  Part 2  Live scenarios: events written to the onboarded log files and to the monitored
          file share; alerts read back from Wazuh's alerts.json
All users, IPs and data are synthetic. Run with `make demo-siem` after `make siem-up`.
"""
import json
import re
import subprocess
import sys
import time
from collections import OrderedDict
from pathlib import Path

import secrets

ROOT = Path(__file__).resolve().parent.parent
# Unique names and IPs per run, so events left in the log files by earlier runs can't
# combine with this run's events in Wazuh's counting rules.
RUN = secrets.token_hex(2)
OCTET = int(RUN, 16) % 200 + 20
DEV, TOOL = f"dev.kamau-{RUN}", f"summariser-tool-{RUN}"
BRUTE_IP, ATTACK_IP, LEAKY_IP = f"203.0.113.{OCTET}", f"198.51.100.{OCTET}", f"10.20.1.{OCTET}"
INSURER = f"insurer-{RUN}"
LOGS = ROOT / "logs"
CONTAINER = "sil-siem-wazuh"
ALERTS = "/var/ossec/logs/alerts/alerts.json"
results = {"pass": 0, "fail": 0}


def check(name, ok, detail=""):
    results["pass" if ok else "fail"] += 1
    print(f"  {'PASS' if ok else 'FAIL'}  {name:<62} {detail}")


def dexec(cmd, stdin=None):
    return subprocess.run(["docker", "exec", "-i", CONTAINER, "bash", "-c", cmd],
                          input=stdin, capture_output=True, text=True)


def logtest(event: dict) -> str:
    """Run one event through wazuh-logtest. It prints its results on stderr, so read both."""
    r = dexec("/var/ossec/bin/wazuh-logtest 2>&1", json.dumps(event) + "\n")
    return r.stdout + r.stderr


def append(rel, events, spacing=0.2):
    """Append JSON lines to a lab log file, a few at a time with small gaps, which is closer to
    real event rates than an instantaneous burst. Files written by lab containers may belong
    to another uid, so fall back to appending as root through a throwaway container."""
    path = LOGS / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    for e in events:
        data = json.dumps(e, separators=(",", ":")) + "\n"
        try:
            with path.open("a") as fh:
                fh.write(data)
        except PermissionError:
            subprocess.run(["docker", "run", "--rm", "-i", "--entrypoint", "sh", "-v", f"{LOGS}:/logs",
                            "wazuh/wazuh-manager:4.14.8", "-c", f"cat >> /logs/{rel}"],
                           input=data, text=True, check=True, capture_output=True)
        time.sleep(spacing)


# ---- synthetic events in each source's real format -------------------------------
def kong(status, ip, consumer=None, uri="/api/claims", route="claims-read"):
    e = {"client_ip": ip, "workspace_name": "default", "upstream_uri": uri.replace("/api", ""),
         "request": {"method": "GET", "uri": uri, "headers": {"user-agent": "python-requests/2.32"}},
         "response": {"status": status}, "route": {"name": route}, "started_at": int(time.time() * 1000)}
    if consumer:
        e["consumer"] = {"username": consumer}
    return e


def waf(ip, rule_ids, uri="/api/patients/search", msg="Attack detected"):
    return {"transaction": {"client_ip": ip, "time_stamp": time.strftime("%a %b %d %H:%M:%S %Y"),
            "request": {"method": "POST", "uri": uri}, "response": {"http_code": 403},
            "messages": [{"message": msg, "details": {"ruleId": r, "severity": "2"}} for r in rule_ids]}}


def ai(reason, client="internal-tool", decision="blocked"):
    return {"event": "ai_request", "request_id": f"demo-{time.time_ns()}", "client_id": client,
            "model": "enterprise-llm", "decision": decision, "reason": reason,
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}


def egress(user, host, bytes_out=1500, action="allowed", ip="10.20.1.15"):
    return {"event": "egress", "username": user, "src_ip": ip, "host": host, "method": "POST",
            "bytes_out": str(bytes_out), "verdict": action,
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}


# ---------------------------------------------------------------------------------
print("== Waiting for Wazuh (analysis engine, log collector, file integrity monitoring)")
deadline = time.time() + 240
while True:
    log = dexec("cat /var/ossec/logs/ossec.log").stdout
    ready = ("Analyzing file: '/lab-logs/egress/proxy.json'" in log
             and "Real-time file integrity monitoring started" in log)
    if ready or time.time() > deadline:
        break
    time.sleep(5)
check("Wazuh manager is ready and collecting the onboarded logs", ready)
if not ready:
    print("        last log lines:\n" + "\n".join(log.splitlines()[-8:]))
    sys.exit(1)
probe = logtest({"event": "ai_request", "reason": "", "client_id": "probe"})
loaded = "id: '100100'" in probe
check("SIL custom rules are loaded", loaded)
if not loaded:
    print("        Wazuh decoded the event but no SIL rule matched, so sil_rules.xml was not loaded.")
    print("        Check: docker exec sil-siem-wazuh ls /var/ossec/etc/rules /var/ossec/etc/lists")
    sys.exit(1)

# ---------------------------------------------------------------------------------
print("\n== Part 1: rule unit tests with wazuh-logtest")
CASES = [
    ("AI gateway: PHI blocked", ai("PHI_DETECTED"), "100101", 10),
    ("AI gateway: credential pasted", ai("SECRET_DETECTED"), "100102", 12),
    ("AI gateway: prompt injection", ai("PROMPT_INJECTION"), "100103", 10),
    ("AI gateway: system prompt leak", ai("SYSTEM_PROMPT_LEAK"), "100104", 12),
    ("AI gateway: allowed request is not alerted", ai("", decision="allowed"), "100100", 0),
    ("Kong: authentication failure", kong(401, "203.0.113.50"), "100201", 5),
    ("Kong: access denied", kong(403, "10.20.1.30", "insurer-client"), "100203", 5),
    ("Kong: rate limited", kong(429, "10.20.1.30", "insurer-client"), "100205", 4),
    ("Kong: normal request is not alerted", kong(200, "10.20.1.30", "hospital-client"), "100200", 0),
    ("WAF: SQL injection", waf("198.51.100.23", ["942100", "949110"]), "100301", 8),
    ("WAF: XSS", waf("198.51.100.23", ["941100", "941110", "949110"]), "100302", 8),
    ("WAF: national ID in URL", waf("10.20.1.40", ["10001"], "/api/patients?national_id=x"), "100303", 10),
    ("Shadow AI: consumer LLM", egress("dev.kamau", "chat.openai.com"), "100401", 8),
    ("Shadow AI: large upload", egress("dev.kamau", "chat.openai.com", 245000), "100402", 12),
    ("Shadow AI: blocked attempt", egress("dev.kamau", "claude.ai", action="denied"), "100404", 5),
    ("Approved AI gateway is not Shadow AI", egress("dev.kamau", "llm-gateway.sil.internal"), "100400", 0),
]
for name, event, want_id, want_level in CASES:
    out = logtest(event)
    ids, levels = re.findall(r"id: '(\d+)'", out), re.findall(r"level: '(\d+)'", out)
    got = (ids[-1], int(levels[-1])) if ids and levels else ("none", -1)
    check(name, got == (want_id, want_level), f"rule {got[0]}, level {got[1]}")

out = logtest(kong(403, "10.20.1.30", "insurer-client"))
fields = [l.strip() for l in out.split("**Phase 2")[1].split("**Phase 3")[0].splitlines()[1:] if ":" in l] \
    if "**Phase 2" in out else []
print("        Onboarding check, fields Wazuh decoded from a Kong log line:")
for f in fields[:8]:
    print(f"          {f}")

# ---------------------------------------------------------------------------------
print(f"\n== Part 2: live attack scenarios (run id {RUN})")
start_line = int(dexec(f"touch {ALERTS}; wc -l < {ALERTS}").stdout.strip() or 0)

print("   a. Shadow AI: a developer uses consumer chatbots instead of the approved gateway")
append("egress/proxy.json", [
    egress(DEV, "llm-gateway.sil.internal", 2000),      # sanctioned: no alert
    egress(DEV, "chat.openai.com", 3100),
    egress(DEV, "chat.openai.com", 245000),             # pasted a large document
    egress(DEV, "claude.ai", action="denied"),
    egress(DEV, "gemini.google.com", 1200),
    egress(DEV, "chat.deepseek.com", 800),
    egress(DEV, "chat.openai.com", 2500),
    egress(DEV, "chatgpt.com", 900),
])
print("   b. Token brute force against the API gateway, and an insurer probing patient data")
append("kong/access.json", [kong(401, BRUTE_IP) for _ in range(15)]
       + [kong(403, "10.20.1.30", INSURER, "/api/patients/search", "patients") for _ in range(8)])
print("   c. Web attack campaign against the WAF, plus a client leaking IDs in URLs")
append("waf/audit.log", [waf(ATTACK_IP, ["942100", "949110"], msg="SQL Injection") for _ in range(6)]
       + [waf(ATTACK_IP, ["941100", "941110", "949110"], msg="XSS")]
       + [waf(LEAKY_IP, ["10001"], "/api/patients?national_id=redacted", "PHI in URL")])
print("   d. An internal tool repeatedly sends PHI and a credential to the AI gateway")
append("ai-guard/audit.json", [ai("PHI_DETECTED", TOOL), ai("PHI_DETECTED", TOOL), ai("SECRET_DETECTED", TOOL),
                               ai("PROMPT_INJECTION", TOOL), ai("PHI_DETECTED", TOOL)])
print("   e. Ransomware encrypts a file share and drops a ransom note")
dexec("for i in $(seq 1 25); do echo \"claim batch $i,KES 4500,synthetic\" > /srv/fileshare/claims_$i.csv; done")
time.sleep(15)   # let file integrity monitoring record the clean files first
dexec("for f in /srv/fileshare/claims_*.csv; do head -c 4096 /dev/urandom > \"$f\"; done; sleep 2; "
      "for f in /srv/fileshare/claims_*.csv; do mv \"$f\" \"$f.locked\"; done; "
      "echo 'Your files are encrypted. Pay to recover.' > /srv/fileshare/README_RESTORE_FILES.txt")

EXPECTED = OrderedDict([
    ("100401", "Shadow AI: consumer LLM accessed"), ("100402", "Shadow AI: large upload"),
    ("100404", "Shadow AI: blocked by allowlist"), ("100403", "Shadow AI: repeated use"),
    ("100202", "Token brute force"), ("100204", "Insurer probing outside permissions"),
    ("100301", "WAF: SQL injection"), ("100303", "WAF: ID in URL"), ("100304", "Active web attack"),
    ("100101", "AI gateway: PHI blocked"), ("100102", "AI gateway: credential sent"),
    ("100105", "Repeated AI policy violations"),
    ("100502", "Mass file modification"), ("100500", "Encryption extension created"),
    ("100501", "Ransom note created"), ("100504", "RANSOMWARE ACTIVE"),
])
def read_alerts():
    """Count alerts by rule id since the scenarios started (rebuilt from scratch each call)."""
    found = {}
    for line in dexec(f"tail -n +{start_line + 1} {ALERTS}").stdout.splitlines():
        try:
            rule = json.loads(line)["rule"]
        except (ValueError, KeyError):
            continue
        s = found.setdefault(rule["id"], {"count": 0, "level": rule["level"], "desc": rule["description"],
                                          "mitre": rule.get("mitre", {}).get("id", [])})
        s["count"] += 1
    return found


print("\n   waiting for alerts (up to 2 minutes)...")
deadline = time.time() + 120
seen = read_alerts()
while not all(k in seen for k in EXPECTED) and time.time() < deadline:
    time.sleep(10)
    seen = read_alerts()

for rid, label in EXPECTED.items():
    s = seen.get(rid)
    check(f"{label} ({rid})", s is not None,
          f"level {s['level']}, {s['count']} alert(s) {','.join(s['mitre'])}" if s else "no alert")

if "100402" not in seen:
    print("\n   Diagnostic: rules that handled this run's 245000-byte upload event:")
    for line in dexec(f"tail -n +{start_line + 1} {ALERTS}").stdout.splitlines():
        try:
            a = json.loads(line)
        except ValueError:
            continue
        d = a.get("data", {})
        if d.get("bytes_out") == "245000" and d.get("username") == DEV:
            print(f"     rule {a['rule']['id']} (level {a['rule']['level']}): verdict={d.get('verdict')!r} "
                  f"bytes_out={d.get('bytes_out')!r} fields={sorted(d)}")

print("\n== Part 3: correlation behaviour (a second client, after Part 2's correlation fired)")
calib = f"calibration-{RUN}"
for _ in range(6):
    append("ai-guard/audit.json", [ai("PHI_DETECTED", calib)])
    time.sleep(3)
order = []
for _ in range(10):
    time.sleep(3)
    order = []
    for line in dexec(f"grep -h '{calib}' {ALERTS}").stdout.splitlines():
        try:
            order.append(json.loads(line)["rule"]["id"])
        except (ValueError, KeyError):
            pass
    if len(order) >= 6:
        break
print("        6 PHI events from a second client -> " + " ".join(order))
check("Events 1-3 alert individually (below threshold)", order[:3] == ["100101"] * 3)
check("Event 4 raises the correlation alert (frequency=4)", order[3:4] == ["100105"])
check("A second offender is not hidden by the first one's alert", "100105" in order)
check("Events 5-6 are still alerted (individually or as correlation)",
      len(order) >= 6 and all(r in ("100101", "100105") for r in order[4:6]))

print("\n== Alerts raised by SIL rules, highest severity first")
for rid, s in sorted(((r, s) for r, s in seen.items() if r.startswith("100")), key=lambda x: -x[1]["level"]):
    print(f"   L{s['level']:<3} {rid}  x{s['count']:<3} {s['desc'][:95]}")

print(f"\nResult: {results['pass']} passed, {results['fail']} failed")
sys.exit(1 if results["fail"] else 0)
