# trace-spill-scanner

**Find the secrets your AI agent's traces are leaking — before Datadog sees them.**

A CLI that scans Claude Platform OpenTelemetry trace exports (GenAI semantic-convention spans) and flags spans carrying API keys, credentials, or PII — a **redaction dry-run** for agent observability. Pairs with the `redact` subcommand, which produces a redacted copy of the export with every hit replaced by `[REDACTED:<class>]`.

## Why this exists (news hook)

On **2026-10-14**, Anthropic announced **Agent Observability with OpenTelemetry trace export** for the Claude Platform — every agent turn, model call, tool use, and MCP server communication can now be exported as traces into your observability stack.

That's powerful — and it's a new exfiltration surface. Agent traces routinely contain the *content* of tool calls: shell commands with embedded credentials, file reads that returned private keys, user messages with emails, SSNs, and card numbers. The moment those traces land in Datadog, Grafana, or Sentry, every person with dashboard access can read them.

`trace-spill-scanner` answers one question before you wire up the export pipeline: **which spans would leak secrets if I shipped these traces as-is?**

Source: [Anthropic Adds OpenTelemetry Trace Export to the Claude Platform](https://www.unite.ai/anthropic-adds-opentelemetry-trace-export-to-the-claude-platform/) (Unite.AI, 2026-10-14).

## Install

```bash
pip install .
# or run without installing:
PYTHONPATH=src python -m tracespill.cli --help
```

Requires Python 3.10+. No dependencies beyond the standard library.

## Usage

```bash
# Scan a trace export (exit 1 if anything found — CI-friendly)
trace-spill-scanner scan trace.json

# Machine-readable output
trace-spill-scanner scan trace.json --json

# Produce a redacted copy
trace-spill-scanner redact trace.json trace.redacted.json
```

Example output:

```
Scanned 7 spans, 19 findings.
  [anthropic_api_key] span='claude.messages.create' span_id=span-llm-call attribute='http.request.header.authorization' (Anthropic API key)
  [aws_access_key_id] span='tool.execute:shell' span_id=span-tool-shell attribute='tool.args.command' (AWS access key ID)
  [private_key] span='mcp.server.filesystem.read' span_id=span-mcp attribute='mcp.response.body' (PEM private key)
  ...

Summary by class:
  anthropic_api_key: 1
  aws_access_key_id: 1
  ...
```

## What it detects

Deterministic, dependency-free detectors (15 classes): Anthropic API keys (`sk-ant-*`), OpenAI API keys, xAI keys, AWS access key IDs + secret keys, GCP API keys, GitHub tokens, PEM private keys, JWTs, Bearer tokens, email addresses, US SSNs, phone numbers, credit card numbers (Luhn-validated), OpenAI org IDs.

## Input format

OTLP JSON exports in either shape:

- `{"resourceSpans": [{"scopeSpans": [{"spans": [...]}]}]}` (what collectors emit), or
- `{"spans": [...]}` (flat convenience shape).

Span attributes use the OTLP `{key, value: {stringValue: ...}}` form; non-string scalars are stringified before scanning.

## Scope notes (honest)

- **Heuristic, not exhaustive.** Regex/Luhn detectors catch common shapes; novel or obfuscated secrets (base64 blobs, split tokens) may pass undetected. Treat a clean scan as "no known shapes found", not "provably clean".
- **No redaction of the pipeline itself.** This tool tells you *what* to redact; wiring an OTLP processor (e.g. the Collector's `redaction` processor) into your live pipeline is still on you.
- The fixture secrets are synthetic test values (e.g. `AKIAIOSFODNN7EXAMPLE`); never use real credentials in fixtures.

## Tests

```bash
PYTHONPATH=src pytest -q
```

## Built by Ingenious AI

Part of the Ingenious AI platform suite — security tooling for the AI-agent era:

- [DisclosureGuard](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20DisclosureGuard.)
- [ModelMinder](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20ModelMinder.)
- [TermsWatch](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20TermsWatch.)
- [Vibe-Code Audit](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Vibe-Code%20Audit.)
- [Rogue-Agent Defense](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Rogue-Agent%20Defense.)
- [BreachHunter](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20BreachHunter.)
- [ChatBreaker](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20ChatBreaker.)
- [Agent Flight Recorder](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Agent%20Flight%20Recorder.)
- [Agent Auth Gateway](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Agent%20Auth%20Gateway.)
- [DomainGuard](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20DomainGuard.)
- [ContentCraft AI](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20ContentCraft%20AI.)

## License

MIT — see [LICENSE](LICENSE).
