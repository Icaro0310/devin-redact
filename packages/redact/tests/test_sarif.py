"""SARIF 2.1.0 output mode for ``scan`` (RD-3).

The SARIF log must never contain the matched secret text — only rule ids
(pattern categories), locations, masked messages and sha256 fingerprints.
"""

import json

from devin_redact import cli, engine
from devin_redact.sarif import SARIF_SCHEMA, SARIF_VERSION, report_to_sarif
from test_scan import CORPUS, FIXTURES, PLANTED, _fp

SECRET_SAMPLES = [v for values in PLANTED.values() for v in values]


def _sarif():
    return report_to_sarif(engine.scan(CORPUS))


def test_sarif_document_shape():
    sarif = _sarif()
    assert sarif["version"] == SARIF_VERSION == "2.1.0"
    assert sarif["$schema"] == SARIF_SCHEMA
    (run,) = sarif["runs"]
    driver = run["tool"]["driver"]
    assert driver["name"] == "devin-redact"
    assert driver["version"]
    rule_ids = {r["id"] for r in driver["rules"]}
    assert rule_ids >= {
        "api_key", "bearer_token", "github_token", "private_key",
        "env_assignment", "devin_pairing_code", "email",
        "absolute_path", "sensitive_tool_output", "project_name",
    }
    assert run["results"]
    assert run["properties"]["publication_status"] == "BLOCKED"


def test_sarif_results_map_findings():
    report = engine.scan(CORPUS)
    sarif = report_to_sarif(report)
    results = sarif["runs"][0]["results"]
    assert len(results) == len(report["findings"])
    rule_ids = {r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]}
    for result in results:
        assert result["ruleId"] in rule_ids
        assert result["level"] in {"error", "warning"}
        assert result["message"]["text"].startswith("match: ")
        loc = result["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"]
        fp = result["partialFingerprints"]["devin-redact/fingerprint"]
        assert len(fp) == 16


def test_sarif_secret_categories_are_errors():
    sarif = _sarif()
    levels = {r["ruleId"]: r["level"] for r in sarif["runs"][0]["results"]}
    assert levels.get("api_key") == "error"
    assert levels.get("private_key") == "error"
    assert levels.get("sensitive_tool_output") == "error"
    assert levels.get("email") == "warning"
    assert levels.get("absolute_path") == "warning"


def test_sarif_never_contains_secret_text():
    report = engine.scan(CORPUS)
    blob = json.dumps(report_to_sarif(report))
    for secret in SECRET_SAMPLES:
        assert secret not in blob, f"leaked secret text: {secret[:12]}…"
    for f in report["findings"]:
        preview = str(f["preview"])
        if preview and preview != "(empty output)":
            assert preview not in blob
    # The sha256 fingerprint is safe and present for deduplication.
    for value in PLANTED["api_key"]:
        assert _fp(value) in blob


def test_sarif_locations():
    report = engine.scan(CORPUS)
    sarif = report_to_sarif(report)
    results = sarif["runs"][0]["results"]
    # A text finding (export.md) carries a real line number.
    text_results = [
        r for r in results
        if r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        .endswith("export.md")
    ]
    assert text_results
    assert any(
        "region" in r["locations"][0]["physicalLocation"]
        and r["locations"][0]["physicalLocation"]["region"]["startLine"] > 0
        for r in text_results
    )
    # A DB finding keeps its table.column#rowid locator in properties.
    db_results = [
        r for r in results
        if r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        .endswith("sessions.db")
    ]
    assert db_results
    assert any(
        "#rowid=" in r["properties"]["location"] for r in db_results
    )


def test_sarif_semantic_finding_message():
    report = engine.scan([FIXTURES / "sessions.db"])
    sarif = report_to_sarif(report)
    sem = [
        r for r in sarif["runs"][0]["results"]
        if r["ruleId"] == "sensitive_tool_output"
    ]
    assert sem
    assert all(r["message"]["text"] == "match: sensitive tool output" for r in sem)
    assert all(r["properties"]["kind"] == "semantic-context" for r in sem)


def test_cli_scan_sarif(capsys):
    assert cli.main(["scan", str(FIXTURES / ".env"), "--format", "sarif"]) == 0
    sarif = json.loads(capsys.readouterr().out)
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "devin-redact"
    assert sarif["runs"][0]["results"]


def test_cli_scan_sarif_report_file(tmp_path, capsys):
    out = tmp_path / "scan.sarif"
    assert cli.main(
        ["scan", str(FIXTURES / ".env"), "--format", "sarif", "--report", str(out)]
    ) == 0
    capsys.readouterr()
    sarif = json.loads(out.read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0"


def test_cli_scan_default_format_unchanged(capsys):
    assert cli.main(["scan", str(FIXTURES / ".env")]) == 0
    report = json.loads(capsys.readouterr().out)
    assert "publication_status" in report
    assert "runs" not in report


def test_sarif_clean_scan_has_empty_results(tmp_path):
    p = tmp_path / "clean.md"
    p.write_text("nothing sensitive here\n", encoding="utf-8")
    sarif = report_to_sarif(engine.scan([p]))
    assert sarif["runs"][0]["results"] == []
    assert sarif["runs"][0]["properties"]["publication_status"] == "CLEAN"
