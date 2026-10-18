.PHONY: up demo demo-ai logs down clean install-tools hooks scan-secrets check-deps scan-vulns demo-sdlc scan-sast demo-dast siem-up siem-down demo-siem siem-alerts

up:
	python3 scripts/bootstrap.py init
	docker compose up -d --build postgres claims-api patient-api mock-llm ai-guard
	docker compose up -d --force-recreate keycloak
	python3 scripts/bootstrap.py kong
	docker compose up -d --force-recreate kong
	docker compose up -d --force-recreate waf
	@echo "Gateway ready at http://localhost:8080 (https://localhost:8443, self-signed)"
	@echo "AI gateway ready at http://localhost:8090 (internal tools only)"

demo:
	bash scripts/demo.sh

demo-ai:
	python3 scripts/demo_ai.py

logs:
	docker compose logs -f waf kong ai-guard

down:
	docker compose down

clean:
	docker compose down -v
	rm -rf .env keycloak/realm-sil.json kong/kong.yml logs

# ---- Section 1B: secure SDLC -------------------------------------------------
install-tools:
	bash scripts/install_tools.sh

hooks:
	@[ -d .git ] || (git init -q && git add . && git commit -qm "Initial lab commit" --no-verify && echo "initialised git repo")
	pre-commit install

scan-secrets:
	gitleaks dir . --config .gitleaks.toml --redact --no-banner

check-deps:
	python3 scripts/check_dependencies.py services/*/requirements.in
	python3 scripts/check_dependencies.py --no-approval-check services/*/requirements.txt

scan-vulns:
	docker run --rm -v "$(PWD):/src:ro" ghcr.io/google/osv-scanner:v2.6.0 scan source -r /src/services

demo-sdlc:
	bash scripts/demo_sdlc.sh

scan-sast:
	docker run --rm -v "$(PWD):/src:ro" semgrep/semgrep:1.178.0 semgrep scan --metrics=off \
	  --config /src/security/semgrep/sil-rules.yaml /src/services

# Enables the deliberately vulnerable endpoint, runs the demo, then always disables it again.
demo-dast:
	LAB_VULNERABLE_ENDPOINTS=true docker compose up -d --build claims-api
	python3 scripts/demo_dast.py; rc=$$?; docker compose up -d claims-api; exit $$rc

# ---- Section 1B Q3: Wazuh SIEM (lean mode) ------------------------------------
siem-up:
	@for f in logs/egress/proxy.json logs/kong/access.json logs/waf/audit.log logs/ai-guard/audit.json; do \
	  mkdir -p $$(dirname $$f); [ -e $$f ] || touch $$f; done
	docker compose -f siem/docker-compose.yml up -d --force-recreate
	@echo "Wazuh starting; first start takes 1-3 minutes. Then: make demo-siem"

siem-down:
	docker compose -f siem/docker-compose.yml down -v

demo-siem:
	python3 scripts/demo_siem.py

siem-alerts:
	docker exec sil-siem-wazuh tail -f /var/ossec/logs/alerts/alerts.log
