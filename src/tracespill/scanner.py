"""Core trace parsing + scanning logic (OTLP JSON exports)."""
from __future__ import annotations

import json
from dataclasses import dataclass, field

from .detectors import scan_value, redact_value


@dataclass
class SpanFinding:
    trace_id: str
    span_id: str
    span_name: str
    attribute: str
    finding_class: str
    label: str


@dataclass
class ScanReport:
    spans_scanned: int = 0
    findings: list[SpanFinding] = field(default_factory=list)

    @property
    def findings_by_class(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.finding_class] = counts.get(f.finding_class, 0) + 1
        return counts


def _iter_spans(trace: dict) -> list[dict]:
    """Accept OTLP JSON in either resourceSpans shape or a flat {"spans": [...]}."""
    spans: list[dict] = []
    if "spans" in trace and isinstance(trace["spans"], list):
        spans.extend(trace["spans"])
    for rs in trace.get("resourceSpans", []) or []:
        for ss in rs.get("scopeSpans", []) or []:
            spans.extend(ss.get("spans", []) or [])
    return spans


def _attribute_value(attr: dict) -> str | None:
    """Extract the string value of an OTLP attribute ({key, value: {stringValue}})."""
    key = attr.get("key", "")
    value = attr.get("value", {})
    if not isinstance(value, dict):
        return None
    if "stringValue" in value:
        return str(value["stringValue"])
    # Non-string scalar/array values: stringify so detectors still see them.
    return json.dumps(value)


def scan_trace(trace: dict) -> ScanReport:
    """Scan every span attribute of an OTLP JSON trace export."""
    report = ScanReport()
    for span in _iter_spans(trace):
        report.spans_scanned += 1
        trace_id = str(span.get("traceId", ""))
        span_id = str(span.get("spanId", ""))
        span_name = str(span.get("name", "<unnamed>"))
        for attr in span.get("attributes", []) or []:
            key = str(attr.get("key", ""))
            val = _attribute_value(attr)
            if val is None:
                continue
            for hit in scan_value(val):
                report.findings.append(SpanFinding(
                    trace_id=trace_id,
                    span_id=span_id,
                    span_name=span_name,
                    attribute=key,
                    finding_class=hit.finding_class,
                    label=hit.label,
                ))
    return report


def redact_trace(trace: dict) -> dict:
    """Return a deep-copied trace with every detected value replaced."""
    import copy
    out = copy.deepcopy(trace)

    def _redact_attrs(span: dict) -> None:
        for attr in span.get("attributes", []) or []:
            value = attr.get("value", {})
            if isinstance(value, dict) and "stringValue" in value:
                value["stringValue"] = redact_value(str(value["stringValue"]))

    if "spans" in out and isinstance(out["spans"], list):
        for span in out["spans"]:
            _redact_attrs(span)
    for rs in out.get("resourceSpans", []) or []:
        for ss in rs.get("scopeSpans", []) or []:
            for span in ss.get("spans", []) or []:
                _redact_attrs(span)
    return out
