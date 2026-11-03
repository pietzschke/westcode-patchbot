from typing import Any

ACTIONABLE_SEVERITIES = frozenset({"CRITICAL", "HIGH", "MEDIUM"})
SEVERITY_RANK = {
    "CRITICAL": 3,
    "HIGH": 2,
    "MEDIUM": 1,
    "LOW": 0,
    "UNKNOWN": 0,
}


def filter_actionable_vulns(raw_vulns: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Keep only vulnerabilities that have an upstream fix and MEDIUM+ severity."""
    actionable: list[dict[str, Any]] = []
    for vuln in raw_vulns:
        status = str(vuln.get("Status") or "").strip()
        severity = str(vuln.get("Severity") or "").strip().upper()
        if status == "fixed" and severity in ACTIONABLE_SEVERITIES:
            actionable.append(vuln)
    return actionable


def extract_vulns_from_trivy_report(report: dict[str, Any]) -> list[dict[str, Any]]:
    """Flatten Trivy JSON Results[].Vulnerabilities into a filtered list of actionable vulns."""
    raw_vulns: list[dict[str, Any]] = []
    for result in report.get("Results") or []:
        for vuln in result.get("Vulnerabilities") or []:
            raw_vulns.append(vuln)
    return filter_actionable_vulns(raw_vulns)
