# Implementation plan: API gateway, WAF and AI gateway (Section 1A b)

## Scope and assumptions

This plan covers inbound API traffic from partner systems (hospitals, insurers) and internal
users, plus outbound traffic from internal tools to enterprise LLMs. Production runs on Google
Cloud; every component also has an open-source equivalent, which the lab in this repo uses.

**Data residency is a prerequisite decision, not a detail.** Health data is sensitive personal
data under Kenya's Data Protection Act 2019, and the Data Protection (General) Regulations 2021
and Digital Health Act 2023 add obligations around where and how it is processed. Before
choosing regions, confirm with legal and the DPO which data must remain in Kenya. If it must, the
design places those datastores in a Kenyan data centre or a hybrid setup, with the cloud hosting
only the edge and stateless tiers.

## Phase 0: Foundations (week 1)

| Area | Decision | Configuration |
|---|---|---|
| Infrastructure as code | Terraform for all cloud resources; Kong config as declarative YAML in Git | No click-ops; every change goes through a pull request with security review |
| Network | Dedicated VPC; separate subnets for edge, application and data tiers | Firewall rules default-deny; Private Service Connect for Cloud SQL; VPC Service Controls perimeter around data projects |
| Secrets and keys | Secret Manager for credentials; Cloud KMS for encryption keys | CMEK on Cloud SQL and storage; key rotation every 90 days; no secrets in images or env files |
| Logging | Every component logs to Cloud Logging, exported to the SIEM | Retention aligned to policy; access to logs is itself logged |

## Phase 1: Identity (week 1 to 2)

Deploy Keycloak on GKE with a Cloud SQL backend and at least two replicas.

Partner systems are machines, so they use the OAuth2 client credentials flow. Each hospital and
insurer gets its own client, its own scopes (`claims:submit`, `claims:read`, `patients:read`)
and a hard-coded organisation claim (`provider_id` or `insurer_id`) that the APIs use for
authorisation. In production these clients authenticate with private-key JWT or mutual TLS
rather than shared secrets.

Staff authenticate with OIDC authorisation code + PKCE, federated to the corporate directory,
with MFA enforced. Access tokens live 5 minutes; refresh tokens are rotated on use.

## Phase 2: WAF (week 2)

Cloud Armor sits in front of the external HTTPS load balancer with the OWASP CRS-based
preconfigured rules, adaptive DDoS protection and SIL-specific custom rules (for example,
blocking national IDs in query strings).

Roll out in two steps to avoid breaking partners:

1. **Detection only for 1 to 2 weeks** at paranoia level 1, with real partner traffic. Review
   every match in the SIEM and write narrow exclusions for genuine false positives.
2. **Blocking mode**, with an agreed process for partners to report false positives and a
   documented emergency bypass that requires two approvers and expires automatically.

## Phase 3: API gateway (week 2 to 3)

Deploy Kong on GKE behind the load balancer, with no public IP of its own. Configuration:

- JWT validation against Keycloak's JWKS endpoint (handles key rotation automatically)
- Per-route ACLs mapping client groups to endpoints
- Rate limits per client, stored in Memorystore (Redis) so all gateway replicas share counters
- Request size limits, correlation IDs, security response headers (`Cache-Control: no-store`
  for any response containing PHI)
- JSON access logs with `Authorization` and `Cookie` headers stripped, exported to the SIEM
- Admin API reachable only from the CI/CD runner's network, never from the internet

## Phase 4: Backend services and data (week 3)

Services run on Cloud Run or GKE with internal-only ingress, so the only path in is through the
gateway. Each service re-validates tokens and enforces organisation-level authorisation itself.

Cloud SQL runs with a private IP, CMEK, automated backups, point-in-time recovery and
`pgaudit`. Each service gets its own database role with minimum privileges. Direct identifiers
(national ID, phone number) receive additional application-layer encryption with keys from
Cloud KMS, and lookups use an HMAC blind index.

## Phase 5: AI gateway (week 3 to 4)

Deploy LiteLLM as the only route to LLM providers, with these guardrails:

- **Input:** prompt-injection detection (LLM Guard), PHI/PII detection and redaction (Microsoft
  Presidio with custom recognisers for Kenyan national IDs, SHA/NHIF numbers, KRA PINs and
  +254 phone numbers), secret detection
- **Output:** PII stripping and content filtering before responses return to the tool
- **Egress:** a firewall allowlist so that only the AI gateway can reach approved provider
  endpoints; any other attempt to reach a known LLM domain is blocked and alerted in the SIEM

Provider selection criteria: a contractual commitment not to train on customer data, a data
processing agreement, regional processing that meets the residency decision from Phase 0, and
zero or minimal data retention.

## Phase 6: Verification and handover (week 4)

| Check | Method | Pass criteria |
|---|---|---|
| Control testing | Automated suite (as in `scripts/demo.sh`) in CI against staging | All checks pass on every deploy |
| DAST | OWASP ZAP API scan against staging, authenticated | No high findings |
| Penetration test | External test before go-live | Critical and high findings remediated |
| Bypass attempts | Try to reach services, Kong admin and the DB directly | All connections refused |
| Load test | Peak claim volume x 2 | Latency added by WAF + gateway under 50 ms at p95 |
| Runbooks | Partner onboarding, key rotation, WAF false-positive handling, incident response | Reviewed and signed off by operations |

## Partner migration

Existing integrations move to the gateway one partner at a time. Each partner gets new
credentials, runs in parallel against the old and new endpoints for a short window, then the
old endpoint is closed for that partner. The old path is decommissioned once the last partner
has moved, rather than being left open indefinitely.
