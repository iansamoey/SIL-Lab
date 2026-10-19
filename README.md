# SIL Infosec Analyst Assessment: Lab

A working lab that implements and tests the controls described in Section 1 of my
SIL Infosec Analyst assessment. Every result shown in the assessment document comes from
the demos in this repository. All users, IP addresses and patient data are synthetic, and no
real credentials are committed (secrets are generated locally into a git-ignored `.env`).

## Start here: where each question is answered

| Assessment question | Where to look | Demo |
|---|---|---|
| 1A (a, c) API gateway, WAF, two sample APIs | `docker-compose.yml`, `kong/`, `waf/`, `services/claims`, `services/patients` | `make demo` (17 checks) |
| 1A (b) Implementation plan | `docs/IMPLEMENTATION_PLAN.md` | |
| 1A (d) Rate limiting, authentication, data handling | `kong/kong.yml.tmpl`, `services/common/auth.py`, `db/init/` | `make demo` |
| 1A (e) AI input/output guardrails | `services/ai_guard/`, `services/mock_llm/` | `make demo-ai` (17 checks) |
| 1B Q2 Secret scanning and hallucinated dependencies | `.gitleaks.toml`, `.pre-commit-config.yaml`, `scripts/check_dependencies.py` | `make demo-sdlc` (5 checks) |
| 1B Q3 SIEM: ransomware, Shadow AI, new log source | `siem/` (config, rules, domain list) | `make siem-up`, `make demo-siem` |
| 1B Q6 DAST in CI/CD and AI-generated logic flaws | `security/semgrep/`, `security/dast/`, `services/claims/ai_generated.py` | `make demo-dast` (7 checks) |
| CI/CD pipeline | `.github/workflows/security.yml` | Runs on every push |
| Unit tests | `tests/` | `pytest tests` |

**Requirements:** Docker with Compose v2, Python 3.10+, `make`, `curl` (on Windows, use WSL2).
About 8 GB of RAM for the lab; the SIEM (`make siem-up`) runs separately in about 1.5 GB.


| Component | Role in the lab | Production equivalent (GCP) |
|---|---|---|
| ModSecurity + OWASP CRS v4 | WAF: OWASP Top 10 protection plus SIL custom rules | Cloud Armor (preconfigured WAF rules) |
| Kong 3.9 (DB-less) | Gateway: JWT validation, ACLs, rate limiting, size limits, logging | Kong on GKE, or Apigee |
| Keycloak 26 | Identity provider, OAuth2 client credentials | Keycloak on GKE with Postgres, HA |
| FastAPI services | Claims API and Patient API (synthetic data only) | Cloud Run / GKE, private ingress only |
| PostgreSQL 16 | Least-privilege role per service, encrypted identifiers | Cloud SQL, private IP, CMEK |

## Run it

Prerequisites: Docker with Compose v2, Python 3.10+, `make`, `curl`. On Windows, use WSL2.

```bash
make up      # generates secrets, starts everything, wires Keycloak's key into Kong
make demo    # runs the security checks below
make down    # stop (make clean also deletes data and generated secrets)
```

The first `make up` takes a few minutes while images download and Keycloak starts.

## What `make demo` proves

| Control | Test | Expected |
|---|---|---|
| Authentication | No token; forged token signature | 401 |
| Happy path | Hospital looks up a patient, submits a claim; insurer reads it | 200 / 201 / 200 |
| Gateway authorisation | Insurer tries to submit a claim or query patients | 403 |
| Object-level authorisation | Insurer INS-001 requests a claim addressed to INS-002 | 404 |
| Mass assignment | Body includes `provider_id` to impersonate another hospital | 422 |
| Input validation | Negative claim amount | 422 |
| WAF: OWASP CRS | SQL injection in JSON body; XSS in query string | 403 |
| WAF: custom rule | National ID sent in a URL query string | 403 |
| WAF: custom rule | Request for `/docs` (internal API map) | 404 |
| Size limit | 100 KB request body | 413 |
| Rate limiting | More than 60 requests per minute from one client | 429 |
| Network isolation | Direct connection to Kong from the host | refused |

Unit tests for the API auth and validation logic run without Docker:

```bash
pip install --require-hashes -r services/ai_guard/requirements.txt
pip install --require-hashes -r services/claims/requirements.txt
pip install pytest
pytest tests
```

## Key design decisions

- **Only the WAF is exposed.** Kong, the APIs and Postgres have no published ports. The
  backend network is `internal: true`, so the APIs also have no route to the internet.
- **Defence in depth on tokens.** Kong verifies the signature, then each service verifies it
  again (issuer, audience, expiry, `RS256` only) and enforces scopes. A request that bypasses
  the gateway still gets nothing.
- **Identity comes from the token, never the body.** A hospital's `provider_id` is a claim
  stamped into its token by Keycloak. Reads are always filtered by the caller's organisation.
- **PHI handling.** National IDs and phone numbers are encrypted in the application before they
  reach the database. Lookups use a keyed HMAC blind index. Responses return masked values.
  Identifiers travel only in request bodies, and the WAF blocks them in URLs.
- **Least privilege in the database.** Each service has its own DB role with `SELECT, INSERT`
  on its own table only. Claims are append-only.
- **Logs are safe to ship.** Kong's JSON access log strips `Authorization` and `Cookie` headers
  before writing. WAF audit logs and Kong logs land in `logs/` for SIEM ingestion (Section 1B).
- **No committed secrets.** `scripts/bootstrap.py` generates every secret into `.env`, which is
  gitignored.

## AI guardrail gateway (Section 1A e)

Internal tools never call an LLM provider directly. They call `ai-guard`, an
OpenAI-compatible proxy that is the only component able to reach the model.

```
internal tool ──► ai-guard :8090 ──► input guardrails ──► LLM ──► output guardrails ──► tool
  (token with      (verifies token,     injection, PHI,     (mock in     strip PII, detect
   ai:use scope)    owns system prompt)  secrets             the lab)     system-prompt leaks)
```

Run `make demo-ai` to exercise it. The lab uses a mock LLM, so no data ever leaves your machine.

| Guardrail | How | Action |
|---|---|---|
| Prompt injection | Weighted patterns after Unicode normalisation (defeats zero-width and look-alike characters) | Block |
| PHI | Presidio with Kenyan recognisers (national ID, +254/07xx phones, KRA PIN, SHA/NHIF numbers) plus ICD-10 and clinical terms. Identifier + clinical context = PHI | Block |
| Personal identifiers alone | Same recognisers | Redact to `<ENTITY_TYPE>` and forward |
| Secrets | Patterns for DB connection strings, passwords, cloud keys, private keys, tokens | Block, with a pointer to the Duty to Report policy |
| PII in responses | Same recognisers on model output | Redact |
| System prompt leak | Random per-request canary in the gateway's system prompt; if it appears in the output, an injection got through | Withhold the response |
| Unscannable content | Images, files and streaming responses can't be inspected | Block |
| Caller system prompts | Dropped: the gateway owns the system prompt | Ignore |

Every request writes a JSON line to `logs/ai-guard/audit.json` with the client, decision,
entity types and counts, and injection score, but never the prompt or response text.
That log is the SIEM feed for AI usage.

Network isolation enforces the design rather than relying on convention: `mock-llm` sits
on its own internal network shared only with `ai-guard`, and the APIs have no internet
route at all, so no other component can reach any LLM, enterprise or consumer.


## Secure AI SDLC: secret scanning and the dependency gate (Section 1B Q2)

```bash
make install-tools   # pinned gitleaks (checksum-verified) and pre-commit
make demo-sdlc       # blocked commit, --no-verify bypass caught, bad dependencies blocked, OSV scan
make hooks           # install the hooks in this repo (initialises git if needed)
```

| Control | Where it runs | What it stops |
|---|---|---|
| gitleaks pre-commit hook (`.pre-commit-config.yaml`) | Developer's machine, every commit | Credentials entering the repo, and therefore the context AI assistants index and suggest from |
| gitleaks full-history scan | CI, every PR | Secrets committed with `--no-verify` |
| Dependency gate (`scripts/check_dependencies.py`) | Pre-commit and CI, whenever a requirements file changes | AI-hallucinated packages (don't exist), slopsquatted ones (registered recently), typosquats, unreviewed additions |
| OSV-Scanner | CI and `make scan-vulns` | Known vulnerabilities in real packages |

Custom gitleaks rules (`.gitleaks.toml`) add database connection strings, our `*_SECRET`/`*_PASSWORD`
convention and OAuth client secrets to the defaults. Test fixtures that contain fake credentials carry
an inline `# gitleaks:allow` with a reason, so every exception is visible in code review.

**Pre-commit scanning is one layer, not the whole answer to Copilot leaks.** It keeps secrets out of
the repository that Copilot indexes, but it cannot see what a developer types into a chat window.
The other layers: Copilot Business/Enterprise with content exclusions for `.env`, key and config
paths; no long-lived secrets on developer machines at all (short-lived credentials from a secret
manager); the AI gateway's secret detection for any LLM traffic we control; and the Duty to Report
policy for the moments when prevention fails.

## DAST in CI/CD and AI-generated logic flaws (Section 1B Q6)

```bash
make up          # once, to register the read-only dast-scanner client
make demo-dast   # SAST + ZAP + two-tenant test against a planted AI-generated flaw
MODE=baseline make demo-dast   # the quick passive scan used on pull requests
```

`services/claims/ai_generated.py` is a deliberately vulnerable endpoint written the way AI
assistants commonly write code: authenticated, scope-checked, parameterised, validated, and
missing the business rule that results must be limited to the caller's organisation. It is
only mounted while `make demo-dast` runs.

| Technique | Catches the flaw? | Why |
|---|---|---|
| Semgrep with SIL custom rules (`security/semgrep/`) | Yes, before merge | The rule encodes our business rule: every query on `claims` must use `org_filter(caller)` |
| OWASP ZAP API scan | No | It scans as one identity, so every response looks legitimate; it finds injection, headers and misconfiguration, not missing business rules |
| Two-tenant authorisation test | Yes, at runtime | Creates data as one organisation and checks another cannot see it |

Minimal pipeline impact: Semgrep only on changed code in PRs (seconds); ZAP passive baseline
after each staging deploy (1-2 minutes, no attack traffic); full active scan nightly; scanner
uses its own read-only identity (`dast-scanner`) with its own rate limit, and the scan scope
excludes write endpoints so shared staging data is never modified.

## SIEM: ransomware, Shadow AI and a new log source (Section 1B Q3)

```bash
make down        # optional: free memory, the SIEM reads the lab's log files without it
make siem-up     # Wazuh manager, lean mode (about 1.5 GB)
make demo-siem   # rule unit tests + live attack scenarios
make siem-down
```

Wazuh runs in lean mode: the manager (decoding, rules, alerts) without the indexer and
dashboard, which need another 3-4 GB. Alerts go to `/var/ossec/logs/alerts/alerts.json`
(`make siem-alerts` follows them live).

| Detection | Source | Rules | MITRE |
|---|---|---|---|
| Ransomware: encryption extensions, ransom notes, mass modification/deletion, correlated "ransomware active" (level 15) | Real-time file integrity monitoring of `/srv/fileshare` | 100500-100504 | T1486, T1485 |
| Shadow AI: consumer LLM access, large uploads, blocked attempts, repeat users | Egress proxy log + `siem/lists/consumer-ai-domains` | 100400-100404 | T1567 |
| AI policy: PHI blocked, credential pasted (Duty to Report), injection, prompt leak, repeat offenders | AI gateway audit log | 100100-100105 | T1552 |
| Token brute force, permission probing, sustained rate limiting | Kong access log (onboarded source) | 100200-100206 | T1110, T1083, T1499 |
| SQLi, XSS, PHI in URLs, active attack campaign | ModSecurity audit log | 100300-100304 | T1190 |

### Onboarding a new log source (worked example: the Kong access log)

1. **Assess.** Owner, format (JSON lines), volume, retention need, and sensitive content. Kong's
   log was already designed to be SIEM-safe: Authorization and Cookie headers are stripped.
2. **Collect.** `<localfile>` with `log_format json` in `siem/config/ossec.conf`, labelled
   `log_source: kong-gateway`. In production, a Wazuh agent on the gateway host ships it.
3. **Parse and map.** Wazuh's built-in JSON decoder; no custom decoder needed. Map vendor field
   names that collide with Wazuh's reserved static fields (`action`, `user`, `srcip`, `url`, ...)
   to non-reserved names: rules can't test static fields with `<field>`, and one invalid rule
   stops Wazuh loading the whole rules file. The demo prints the decoded
   fields (`response.status`, `consumer.username`, `client_ip`, ...) to prove it.
4. **Detect.** Rules on decoded fields (`siem/rules/sil_rules.xml`, 100200-100206), each with a
   description that tells the analyst what happened and what to do.
5. **Test.** Every rule has a `wazuh-logtest` case (demo Part 1) that runs before deployment,
   including negative cases (normal traffic must *not* alert).
6. **Validate live.** Replay realistic events and confirm the alerts fire (demo Part 2).
7. **Calibrate correlation rules against the engine.** A controlled test (demo Part 3) showed
   that a Wazuh rule with `frequency="N"` fires on the Nth event, and that once it fires it
   *replaces* the individual alerts for later events in its window. The correlation alert
   therefore carries the triggering reason, and the credential-exposure alert is kept out of
   correlation so it can never be absorbed. An `ignore` window was tried and removed: it
   silences the rule for every source, so a second offender would go unseen.
8. **Monitor the source itself.** Alert if the source goes silent; a missing log is often the
   first sign of tampering or a broken pipeline.

The egress proxy log stands in for a secure web gateway or DNS resolver log; in production
that is the authoritative Shadow AI source, alongside endpoint DLP.

## Dependency lock files

Each service has `requirements.in` (the direct dependencies, which are the decisions a developer
or AI assistant makes) and `requirements.txt`, a lock file pinning every package, transitive ones
included, to an exact version with hashes. Docker builds install with `--require-hashes`, so a
tampered or substituted package fails the build. Lock files are generated with
`uv pip compile --generate-hashes --exclude-newer <date 14 days ago>`, which enforces the two-week
release-age rule at resolution time rather than by manual checking.

## Lab shortcuts (and what production does instead)

| Lab | Production |
|---|---|
| Keycloak `start-dev`, in-memory DB | `start` mode, Postgres backend, TLS, HA replicas |
| Kong gets Keycloak's public key at bootstrap | Gateway validates against the JWKS endpoint so key rotation is automatic |
| Client secret authentication | Private-key JWT or mTLS for partner systems |
| Mock LLM, guard code in FastAPI | Enterprise LLM endpoint; guard logic as LiteLLM custom guardrails, with per-team budgets |
| HTTP between containers | mTLS between gateway and services (service mesh) |
| Self-signed cert on the WAF | Managed certificates, TLS 1.2+ only |
| Encryption keys in `.env` | Cloud KMS / Vault, with envelope encryption and rotation |
| Rate limits stored per Kong node | Redis-backed limits shared across gateway replicas |

## Troubleshooting

- **Every request returns 401 after restarting Keycloak.** Lab Keycloak generates a new signing
  key on each fresh start. Run `python3 scripts/bootstrap.py kong && docker compose restart kong`.
  (This is exactly why production validates against JWKS instead.)
- **A legitimate request gets 403 from the WAF.** Check `logs/waf/audit.log` for the rule ID,
  then add a narrow exclusion in `waf/sil-custom-rules.conf`. Don't lower the paranoia level globally.
