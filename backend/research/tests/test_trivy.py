import json
import subprocess
from pathlib import Path

from research.trivy import run_trivy_fs, run_trivy_image

REPORT = {"Results": [
    {"Target": "package-lock.json", "Class": "lang-pkgs", "Type": "npm", "Vulnerabilities": [
        {"VulnerabilityID": "CVE-2026-0001", "PkgName": "lodash", "InstalledVersion": "4.17.15",
         "FixedVersion": "4.17.21", "Severity": "HIGH", "Status": "fixed", "Title": "Prototype pollution"},
        {"VulnerabilityID": "CVE-2026-0002", "PkgName": "lodash", "InstalledVersion": "4.17.15",
         "FixedVersion": "4.17.21", "Severity": "LOW", "Status": "fixed"},
        {"VulnerabilityID": "CVE-2026-0003", "PkgName": "minimist", "InstalledVersion": "1.2.0",
         "Severity": "CRITICAL", "Status": "affected"},
        {"VulnerabilityID": "CVE-2026-0004", "PkgName": "semver", "InstalledVersion": "5.7.1",
         "FixedVersion": "5.7.2, 6.3.1, 7.5.2", "Severity": "MEDIUM", "Status": "fixed"},
    ]},
]}


def test_parses_and_keeps_only_fixed_medium_plus():
    result = run_trivy_fs(Path("/repo"), runner=lambda argv, timeout: (0, json.dumps(REPORT), ""))
    assert result.status == "OK"
    assert [v["id"] for v in result.vulnerabilities] == ["CVE-2026-0001", "CVE-2026-0004"]
    lodash = result.vulnerabilities[0]
    assert (lodash["ecosystem"], lodash["pkg_class"], lodash["fixed"], lodash["title"]) == (
        "npm", "lang-pkgs", "4.17.21", "Prototype pollution",
    )


def test_multi_branch_fixed_version_picks_lowest_upgrade():
    result = run_trivy_fs(Path("/repo"), runner=lambda argv, timeout: (0, json.dumps(REPORT), ""))
    assert result.vulnerabilities[1]["fixed"] == "5.7.2"


def test_nonzero_exit_is_failed_not_clean():
    result = run_trivy_fs(Path("/repo"), runner=lambda argv, timeout: (2, "", "FATAL db error"))
    assert result.status == "FAILED"
    assert "db error" in result.error
    assert result.vulnerabilities == []


def test_timeout_is_failed():
    def runner(argv, timeout):
        raise subprocess.TimeoutExpired(argv, timeout)

    assert run_trivy_fs(Path("/repo"), runner=runner).status == "FAILED"


def test_missing_binary_is_failed():
    def runner(argv, timeout):
        raise FileNotFoundError("trivy")

    assert run_trivy_fs(Path("/repo"), runner=runner).status == "FAILED"


def test_invalid_json_is_failed():
    assert run_trivy_fs(Path("/repo"), runner=lambda argv, timeout: (0, "not json", "")).status == "FAILED"


def test_fs_scan_uses_shared_db():
    seen = []

    def runner(argv, timeout):
        seen.append(argv)
        return (0, json.dumps({"Results": []}), "")

    run_trivy_fs(Path("/repo"), runner=runner)
    assert seen[0][:2] == ["trivy", "fs"]
    assert "--skip-db-update" in seen[0]
    assert seen[0][-1] == "/repo"


def test_image_scan_uses_digest_reference_and_shared_db():
    seen = []

    def runner(argv, timeout):
        seen.append(argv)
        return (0, json.dumps({"Results": []}), "")

    run_trivy_image("123.dkr.ecr.eu-central-1.amazonaws.com/materialdatenbank@sha256:d1", runner=runner)
    assert seen[0][:2] == ["trivy", "image"]
    assert seen[0][-1].endswith("@sha256:d1")
    assert "--skip-db-update" in seen[0]
