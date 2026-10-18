#!/usr/bin/env python3
"""Dependency gate: catches AI-hallucinated, typosquatted and brand-new packages.

AI coding assistants regularly suggest packages that do not exist. Attackers watch
for those names and register them with malicious code ("slopsquatting"), so the
next developer who trusts the suggestion installs malware. Vulnerability scanners
(OSV-Scanner, Trivy) can't help here: a malicious package registered last week has
no CVE yet. This gate checks the *package itself* before it enters the codebase.

Checks per dependency (PyPI for requirements*.txt, npm for package.json):
  FAIL  package does not exist on the registry        -> likely hallucinated
  FAIL  name is 1-2 edits away from a popular package -> likely typosquat
  FAIL  package first published < MIN_PACKAGE_AGE_DAYS -> too new to trust
  FAIL  pinned version does not exist
  WARN  pinned version published < COOLDOWN_DAYS ago -> wait for the community to vet it
  WARN  not on the approved list                       -> needs a security review
  WARN  direct URL dependency from an unapproved host

Usage: check_dependencies.py [--format text|defectdojo] FILE...
Exit code 1 if any FAIL, so CI and pre-commit block the change. Standard library only.
"""
import argparse
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

MIN_PACKAGE_AGE_DAYS = 90
COOLDOWN_DAYS = 14
APPROVED_FILE = Path(__file__).resolve().parent.parent / "security/deps/approved.txt"
APPROVED_URL_HOSTS = {"github.com"}  # e.g. spaCy model wheels from github.com/explosion

# Most-downloaded packages that typosquatters target. Extend with your own stack.
POPULAR_PYPI = {
    "requests", "urllib3", "boto3", "botocore", "numpy", "pandas", "setuptools", "six",
    "certifi", "idna", "charset-normalizer", "python-dateutil", "pyyaml", "typing-extensions",
    "cryptography", "pyjwt", "jwt", "fastapi", "flask", "django", "djangorestframework",
    "sqlalchemy", "psycopg", "psycopg2", "psycopg2-binary", "pydantic", "uvicorn", "starlette",
    "httpx", "aiohttp", "jinja2", "click", "pytest", "attrs", "packaging", "pip", "wheel",
    "scipy", "matplotlib", "pillow", "redis", "celery", "openai", "anthropic", "langchain",
    "transformers", "torch", "tensorflow", "scikit-learn", "beautifulsoup4", "lxml", "paramiko",
    "google-cloud-storage", "azure-identity", "presidio-analyzer", "presidio-anonymizer", "spacy",
}
POPULAR_NPM = {
    "react", "react-dom", "express", "lodash", "axios", "chalk", "commander", "debug", "moment",
    "dotenv", "jsonwebtoken", "uuid", "next", "vue", "typescript", "webpack", "jest", "mongoose",
}


def normalise(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def edit_distance(a: str, b: str) -> int:
    if abs(len(a) - len(b)) > 2:
        return 3
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def parse_requirements(path: Path):
    for raw in path.read_text().splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "git+")):
            continue
        if " @ " in line:
            name, url = (s.strip() for s in line.split(" @ ", 1))
            yield {"ecosystem": "pypi", "name": re.sub(r"\[.*\]", "", name), "version": None, "url": url}
            continue
        m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*(==\s*([^\s;,]+))?", line)
        if m:
            yield {"ecosystem": "pypi", "name": m.group(1), "version": m.group(4), "url": None}


def parse_package_json(path: Path):
    data = json.loads(path.read_text())
    for section in ("dependencies", "devDependencies"):
        for name, spec in data.get(section, {}).items():
            version = spec if re.fullmatch(r"\d+\.\d+\.\d+", spec) else None
            yield {"ecosystem": "npm", "name": name, "version": version, "url": None}


def fetch_json(url: str):
    req = urllib.request.Request(url, headers={"User-Agent": "sil-dependency-gate/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise


def registry_info(ecosystem: str, name: str) -> dict | None:
    """Return {'first': datetime, 'versions': {version: datetime}} or None if not found."""
    if ecosystem == "pypi":
        data = fetch_json(f"https://pypi.org/pypi/{urllib.parse.quote(name)}/json")
        if data is None:
            return None
        versions = {}
        for v, files in data.get("releases", {}).items():
            times = [f["upload_time_iso_8601"] for f in files if f.get("upload_time_iso_8601")]
            if times:
                versions[v] = datetime.fromisoformat(min(times).replace("Z", "+00:00"))
    else:
        data = fetch_json(f"https://registry.npmjs.org/{urllib.parse.quote(name, safe='@')}")
        if data is None:
            return None
        times = data.get("time", {})
        versions = {v: datetime.fromisoformat(t.replace("Z", "+00:00"))
                    for v, t in times.items() if v not in ("created", "modified")}
    if not versions:
        return {"first": None, "versions": {}}
    return {"first": min(versions.values()), "versions": versions}


def load_approved() -> set:
    if not APPROVED_FILE.exists():
        return set()
    return {normalise(l.split("#")[0].strip()) for l in APPROVED_FILE.read_text().splitlines()
            if l.split("#")[0].strip()}


def check(dep: dict, approved: set, lookup=registry_info, now=None) -> list[tuple[str, str]]:
    now = now or datetime.now(timezone.utc)
    name, eco = normalise(dep["name"]), dep["ecosystem"]
    popular = POPULAR_PYPI if eco == "pypi" else POPULAR_NPM
    findings = []

    if dep["url"]:
        host = urllib.parse.urlparse(dep["url"]).hostname or ""
        if host not in APPROVED_URL_HOSTS:
            findings.append(("WARN", f"direct URL dependency from unapproved host {host}"))
        if name not in approved:
            findings.append(("WARN", "not on the approved list: needs security review"))
        return findings

    if name not in popular:
        close = sorted(p for p in popular if edit_distance(name, p) <= 2 and len(name) > 3)
        if close:
            findings.append(("FAIL", f"name is very close to popular package '{close[0]}': possible typosquat"))

    info = lookup(eco, dep["name"])
    if info is None:
        findings.append(("FAIL", f"does not exist on {eco}: likely AI-hallucinated. "
                                 "Do not create or install it; find the real package"))
        return findings

    if info["first"] is not None:
        age = (now - info["first"]).days
        if age < MIN_PACKAGE_AGE_DAYS:
            findings.append(("FAIL", f"package first published {age} days ago "
                                     f"(minimum {MIN_PACKAGE_AGE_DAYS}): too new to trust"))
    if dep["version"]:
        published = info["versions"].get(dep["version"])
        if published is None:
            findings.append(("FAIL", f"pinned version {dep['version']} does not exist"))
        elif (now - published).days < COOLDOWN_DAYS:
            findings.append(("WARN", f"version {dep['version']} published {(now - published).days} days ago "
                                     f"(cooldown {COOLDOWN_DAYS})"))
    if name not in approved:
        findings.append(("WARN", "not on the approved list: needs security review"))
    return findings


def to_defectdojo(results) -> dict:
    """DefectDojo 'Generic Findings Import' format."""
    sev = {"FAIL": "High", "WARN": "Low"}
    return {"findings": [
        {"title": f"{dep['name']}: {msg.split(':')[0]}", "severity": sev[level],
         "description": f"{dep['ecosystem']} package {dep['name']} in {src}: {msg}",
         "file_path": src, "component_name": dep["name"], "component_version": dep["version"] or "",
         "vuln_id_from_tool": "dependency-gate", "active": True, "verified": False}
        for src, dep, level, msg in results]}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("files", nargs="+", type=Path)
    ap.add_argument("--format", choices=["text", "defectdojo"], default="text")
    args = ap.parse_args()

    approved, results, fails = load_approved(), [], 0
    for path in args.files:
        parser = parse_package_json if path.name == "package.json" else parse_requirements
        for dep in parser(path):
            for level, msg in check(dep, approved):
                results.append((str(path), dep, level, msg))
                fails += level == "FAIL"

    if args.format == "defectdojo":
        print(json.dumps(to_defectdojo(results), indent=2))
    else:
        for src, dep, level, msg in results:
            print(f"{level:4}  {dep['name']:<28} {msg}   [{src}]")
        print(f"\n{fails} blocking finding(s)" if fails else "\nNo blocking findings.")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
