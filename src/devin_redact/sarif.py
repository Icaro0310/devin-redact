"""SARIF 2.1.0 emitter — converts the ``scan`` report into a
code-scanning/CI-ingestible document.

The SARIF output follows the same secrecy contract as the JSON report:
it **never** carries the matched secret text. Each result contains only
the rule id (the pattern category), the location (file plus the
``table.column#rowid`` / line detail the scan already reports), a masked
message (``"match: aws access key id"``) and the sha256 fingerprint for
deduplication.
"""

from __future__ import annotations

import re

from .engine import _BLOCKING_CATEGORIES
from .patterns import PATTERNS

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFORMATION_URI = "https://github.com/Icaro0310/devin-redact"

# Categories reported by the scan that are not regex patterns.
_EXTRA_CATEGORIES = ("sensitive_tool_output", "project_name")

_LINE_RE = re.compile(r":line (\d+)$")


def _humanize(name: str) -> str:
    return name.replace("_", " ")


def _rules() -> list[dict]:
    """One rule descriptor per pattern category the scanner can emit."""
    rules: list[dict] = []
    for category in sorted(set(PATTERNS) | set(_EXTRA_CATEGORIES)):
        rules.append(
            {
                "id": category,
                "name": category,
                "shortDescription": {
                    "text": f"{_humanize(category)} detection"
                },
                "fullDescription": {
                    "text": (
                        f"devin-redact detected a {category} finding "
                        "(matched text is never included in this log)."
                    )
                },
                "helpUri": INFORMATION_URI,
                "properties": {
                    "category": (
                        "secret"
                        if category in _BLOCKING_CATEGORIES
                        else "pii/hygiene"
                    )
                },
            }
        )
    return rules


def _result_level(category: str) -> str:
    return "error" if category in _BLOCKING_CATEGORIES else "warning"


def _message(finding: dict) -> str:
    if finding.get("kind") == "semantic-context":
        return "match: sensitive tool output"
    return f"match: {_humanize(str(finding.get('pattern') or finding['category']))}"


def _locations(finding: dict) -> tuple[list[dict], dict]:
    """Build the SARIF location list plus extra properties.

    Text findings carry ``...:line N`` in their ``location`` — that maps to
    ``region.startLine``. SQLite findings carry ``table.column#rowid=N``,
    which has no SARIF equivalent, so it is preserved verbatim in
    ``properties.location``.
    """
    file_uri = str(finding["file"]).replace("\\", "/")
    location = str(finding.get("location", ""))
    physical: dict = {"artifactLocation": {"uri": file_uri}}
    m = _LINE_RE.search(location)
    if m:
        physical["region"] = {"startLine": int(m.group(1))}
    props: dict = {"location": location}
    return [{"physicalLocation": physical}], props


def _result(finding: dict) -> dict:
    category = str(finding["category"])
    locations, props = _locations(finding)
    if finding.get("kind"):
        props["kind"] = str(finding["kind"])
    if finding.get("reason"):
        props["reason"] = str(finding["reason"])
    if finding.get("target"):
        props["target"] = str(finding["target"])
    return {
        "ruleId": category,
        "level": _result_level(category),
        "message": {"text": _message(finding)},
        "locations": locations,
        "partialFingerprints": {
            "devin-redact/fingerprint": str(finding["fingerprint"])
        },
        "properties": props,
    }


def report_to_sarif(report: dict) -> dict:
    """Convert a ``scan()`` report dict into a SARIF 2.1.0 log."""
    return {
        "version": SARIF_VERSION,
        "$schema": SARIF_SCHEMA,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "devin-redact",
                        "version": str(report.get("version", "")),
                        "informationUri": INFORMATION_URI,
                        "rules": _rules(),
                    }
                },
                "results": [_result(f) for f in report.get("findings", [])],
                "properties": {
                    "publication_status": report.get("publication_status"),
                    "files_scanned": report.get("files_scanned"),
                },
            }
        ],
    }
