"""Tests for trace-spill-scanner."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from tracespill.detectors import DETECTORS, scan_value, redact_value
from tracespill.scanner import scan_trace, redact_trace

ROOT = Path(__file__).resolve().parent.parent
DIRTY = ROOT / "fixtures" / "dirty-trace.json"
CLEAN = ROOT / "fixtures" / "clean-trace.json"


def _load(p: Path) -> dict:
    return json.loads(p.read_text(encoding="utf-8"))


def test_all_detector_classes_fire_on_dirty_fixture():
    report = scan_trace(_load(DIRTY))
    assert report.spans_scanned == 7
    found = {f.finding_class for f in report.findings}
    expected = {cls for cls, _ in DETECTORS}
    missing = expected - found
    assert not missing, f"detector classes never fired: {missing}"


def test_span_attribution_is_correct():
    report = scan_trace(_load(DIRTY))
    by_span = {}
    for f in report.findings:
        by_span.setdefault(f.span_id, set()).add(f.finding_class)
    assert "anthropic_api_key" in by_span["span-llm-call"]
    assert "bearer_token" in by_span["span-llm-call"]
    assert "aws_access_key_id" in by_span["span-tool-shell"]
    assert "private_key" in by_span["span-mcp"]
    assert "jwt_token" in by_span["span-jwt"]
    assert "credit_card" in by_span["span-user-msg"]
    assert "ssn" in by_span["span-user-msg"]
    assert "email" in by_span["span-user-msg"]
    assert "phone" in by_span["span-user-msg"]
    assert "span-clean" not in by_span


def test_clean_fixture_has_zero_findings():
    report = scan_trace(_load(CLEAN))
    assert report.spans_scanned == 2
    assert report.findings == []


def test_redact_removes_all_secrets_and_stays_valid_json(tmp_path):
    redacted = redact_trace(_load(DIRTY))
    out = tmp_path / "redacted.json"
    out.write_text(json.dumps(redacted), encoding="utf-8")
    # Still valid JSON on reload.
    reloaded = json.loads(out.read_text(encoding="utf-8"))
    # No findings remain.
    assert scan_trace(reloaded).findings == []
    # Placeholders present, raw secret gone.
    blob = out.read_text(encoding="utf-8")
    assert "[REDACTED:anthropic_api_key]" in blob
    assert "[REDACTED:private_key]" in blob
    assert "AKIAIOSFODNN7EXAMPLE" not in blob
    assert "alice.wonderland@example.com" not in blob


def test_redact_preserves_trace_structure():
    original = _load(DIRTY)
    redacted = redact_trace(original)
    assert redacted["resourceSpans"][0]["scopeSpans"][0]["spans"][6]["spanId"] == "span-clean"
    # Original untouched.
    assert "AKIAIOSFODNN7EXAMPLE" in json.dumps(original)


def test_scan_value_units():
    assert any(f.finding_class == "email"
               for f in scan_value("contact bob@example.com today"))
    assert any(f.finding_class == "credit_card"
               for f in scan_value("card 4111 1111 1111 1111"))
    assert not any(f.finding_class == "credit_card"
                   for f in scan_value("card 4111 1111 1111 1112"))  # bad Luhn
    assert any(f.finding_class == "phone" for f in scan_value("call 555-867-5309"))
    assert not scan_value("nothing sensitive here, just a chat log")


def test_redact_value_units():
    out = redact_value("key sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 done")
    assert out == "key [REDACTED:anthropic_api_key] done"
    assert redact_value("plain text") == "plain text"


def test_cli_scan_dirty_exit_code():
    r = subprocess.run(
        [sys.executable, "-m", "tracespill.cli", "scan", str(DIRTY)],
        capture_output=True, text=True,
        env={"PYTHONPATH": str(ROOT / "src"), "PATH": "/usr/bin:/bin"},
        cwd=str(ROOT),
    )
    assert r.returncode == 1, r.stdout + r.stderr
    assert "anthropic_api_key" in r.stdout


def test_cli_scan_clean_exit_code():
    r = subprocess.run(
        [sys.executable, "-m", "tracespill.cli", "scan", str(CLEAN)],
        capture_output=True, text=True,
        env={"PYTHONPATH": str(ROOT / "src"), "PATH": "/usr/bin:/bin"},
        cwd=str(ROOT),
    )
    assert r.returncode == 0, r.stdout + r.stderr
    assert "0 findings" in r.stdout


def test_cli_scan_json_output_schema():
    r = subprocess.run(
        [sys.executable, "-m", "tracespill.cli", "scan", "--json", str(DIRTY)],
        capture_output=True, text=True,
        env={"PYTHONPATH": str(ROOT / "src"), "PATH": "/usr/bin:/bin"},
        cwd=str(ROOT),
    )
    payload = json.loads(r.stdout)
    assert payload["spans_scanned"] == 7
    assert payload["findings_count"] > 0
    first = payload["findings"][0]
    for key in ("trace_id", "span_id", "span_name", "attribute", "class", "label"):
        assert key in first
