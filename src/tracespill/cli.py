#!/usr/bin/env python3
"""trace-spill-scanner CLI.

scan <trace.json>   - report spans carrying secrets/PII (exit 1 if any)
redact <in> <out>   - write a redacted copy of the trace export
"""
from __future__ import annotations

import argparse
import json
import sys

from tracespill.scanner import scan_trace, redact_trace


def _load(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def cmd_scan(args: argparse.Namespace) -> int:
    try:
        trace = _load(args.trace)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: cannot read {args.trace}: {exc}", file=sys.stderr)
        return 2
    report = scan_trace(trace)
    if args.json:
        payload = {
            "spans_scanned": report.spans_scanned,
            "findings_count": len(report.findings),
            "findings": [
                {
                    "trace_id": f.trace_id,
                    "span_id": f.span_id,
                    "span_name": f.span_name,
                    "attribute": f.attribute,
                    "class": f.finding_class,
                    "label": f.label,
                }
                for f in report.findings
            ],
        }
        print(json.dumps(payload, indent=2))
    else:
        print(f"Scanned {report.spans_scanned} spans, "
              f"{len(report.findings)} findings.")
        for f in report.findings:
            print(f"  [{f.finding_class}] span={f.span_name!r} "
                  f"span_id={f.span_id} attribute={f.attribute!r} "
                  f"({f.label})")
        if report.findings:
            print("\nSummary by class:")
            for cls, count in sorted(report.findings_by_class.items()):
                print(f"  {cls}: {count}")
    return 1 if report.findings else 0


def cmd_redact(args: argparse.Namespace) -> int:
    try:
        trace = _load(args.input)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: cannot read {args.input}: {exc}", file=sys.stderr)
        return 2
    redacted = redact_trace(trace)
    with open(args.output, "w", encoding="utf-8") as fh:
        json.dump(redacted, fh, indent=2)
    report = scan_trace(redacted)
    print(f"Wrote redacted trace to {args.output} "
          f"(residual findings: {len(report.findings)})")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="trace-spill-scanner",
        description="Redaction dry-run for GenAI agent observability traces: "
                    "flag secrets/PII in OTLP span attributes before they "
                    "land in Datadog/Grafana/Sentry.")
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="Scan a trace export for secrets/PII")
    p_scan.add_argument("trace", help="OTLP JSON trace export file")
    p_scan.add_argument("--json", action="store_true",
                        help="Machine-readable JSON output")
    p_scan.set_defaults(func=cmd_scan)

    p_redact = sub.add_parser("redact",
                              help="Write a redacted copy of a trace export")
    p_redact.add_argument("input", help="OTLP JSON trace export file")
    p_redact.add_argument("output", help="Destination for redacted JSON")
    p_redact.set_defaults(func=cmd_redact)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
