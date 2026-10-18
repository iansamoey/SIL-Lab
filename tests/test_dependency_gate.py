"""Unit tests for the dependency gate, with a fake registry (no network needed)."""
import importlib.util
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("gate", ROOT / "scripts/check_dependencies.py")
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)

NOW = datetime(2026, 10, 15, tzinfo=timezone.utc)


def registry(packages):
    def lookup(ecosystem, name):
        if name not in packages:
            return None
        versions = {v: NOW - timedelta(days=d) for v, d in packages[name].items()}
        return {"first": min(versions.values()), "versions": versions}
    return lookup


def levels(dep, packages, approved=frozenset()):
    return [lvl for lvl, _ in gate.check(dep, set(approved), lookup=registry(packages), now=NOW)]


def dep(name, version=None, url=None, eco="pypi"):
    return {"ecosystem": eco, "name": name, "version": version, "url": url}


def test_established_approved_package_passes():
    assert levels(dep("fastapi", "0.115.6"), {"fastapi": {"0.115.6": 400}}, {"fastapi"}) == []


def test_hallucinated_package_fails():
    assert "FAIL" in levels(dep("fastapi-jwt-guard", "1.2.0"), {})


def test_slopsquatted_package_registered_last_week_fails():
    # The attack: someone registered the hallucinated name 5 days ago.
    assert "FAIL" in levels(dep("fastapi-jwt-guard", "1.2.0"), {"fastapi-jwt-guard": {"1.2.0": 5}})


def test_typosquat_fails_even_if_it_exists():
    assert "FAIL" in levels(dep("reqeusts", "2.31.0"), {"reqeusts": {"2.31.0": 900}})


def test_popular_package_is_not_its_own_typosquat():
    assert levels(dep("requests", "2.32.3"), {"requests": {"2.32.3": 300}}, {"requests"}) == []


def test_nonexistent_pinned_version_fails():
    assert "FAIL" in levels(dep("fastapi", "9.9.9"), {"fastapi": {"0.115.6": 400}}, {"fastapi"})


def test_brand_new_version_of_trusted_package_warns():
    assert levels(dep("fastapi", "0.200.0"), {"fastapi": {"0.115.6": 400, "0.200.0": 3}},
                  {"fastapi"}) == ["WARN"]


def test_unapproved_package_warns():
    assert levels(dep("rich", "13.0.0"), {"rich": {"13.0.0": 700}}) == ["WARN"]


def test_name_normalisation():
    assert gate.normalise("PyJWT") == gate.normalise("pyjwt")
    assert gate.normalise("en_core_web_sm") == "en-core-web-sm"


def test_parses_extras_urls_and_comments(tmp_path):
    f = tmp_path / "requirements.txt"
    f.write_text("uvicorn[standard]==0.32.1  # server\n"
                 "en_core_web_sm @ https://github.com/explosion/x.whl\n# comment\n-r other.txt\n")
    deps = list(gate.parse_requirements(f))
    assert [(d["name"], d["version"]) for d in deps] == [("uvicorn", "0.32.1"), ("en_core_web_sm", None)]
    assert deps[1]["url"].startswith("https://github.com")
