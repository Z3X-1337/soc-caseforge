# SOC CaseForge

SOC CaseForge is a local-first Python workspace for turning sanitized analyst evidence into a structured incident case. It stores cases in SQLite, parses supported OpenSSH authentication events, extracts common indicators, applies deterministic detection heuristics, and renders Markdown or JSON reports.

It is designed as a portfolio-grade SOC workflow and an early product foundation. It is not a SIEM, EDR, malware sandbox, or autonomous analyst.

## Why this project exists

Small scripts often stop at a single detection or output format. SOC CaseForge connects the workflow:

1. create a case;
2. ingest evidence;
3. preserve a timeline;
4. extract indicators;
5. run explainable detections;
6. produce a reviewable report.

All processing is local. No evidence is uploaded to an external service.

## Current capabilities

- SQLite-backed case storage.
- OpenSSH failed and accepted authentication parsing.
- IPv4 and IPv6 support.
- IOC extraction for URLs, domains, email addresses, IPs, and common hashes.
- Repeated-failure, password-spray-style, and success-after-failure findings.
- Evidence and confidence attached to every finding.
- MITRE ATT&CK assistance for T1110 and T1110.003.
- Markdown and JSON reporting.
- Installable `soc-caseforge` CLI.
- Standard-library runtime with no external dependencies.

## Installation

```bash
python -m pip install .
```

For an isolated command-line installation:

```bash
pipx install .
```

## Quick start

```bash
soc-caseforge --db cases.db init
soc-caseforge --db cases.db new --title "Suspicious SSH activity" --analyst "Zaid Hijazi"
soc-caseforge --db cases.db ingest 1 samples/openssh_demo.log --source openssh
soc-caseforge --db cases.db analyze 1 --failed-threshold 3 --spray-threshold 3
soc-caseforge --db cases.db report 1 --format markdown --output case-1.md
```

Run the built-in demo:

```bash
soc-caseforge --db demo.db demo
```

## Commands

| Command | Purpose |
| --- | --- |
| `init` | Initialize the SQLite database. |
| `new` | Create a case. |
| `list` | List cases. |
| `ingest` | Parse evidence and extract indicators. |
| `analyze` | Run deterministic detection heuristics. |
| `report` | Render Markdown or JSON. |
| `demo` | Create a sanitized demonstration case. |

## Validation

```bash
python -m unittest discover -s tests -v
python -m pip install .
soc-caseforge --help
```

## Architecture

See [docs/architecture.md](docs/architecture.md) and [docs/threat-model.md](docs/threat-model.md).

## Safety and limitations

- Use only evidence you own or are authorized to analyze.
- Do not commit production logs, credentials, tokens, private IP inventories, or customer data.
- Findings are deterministic heuristics, not proof of malicious intent.
- ATT&CK mappings require analyst validation.
- The current parser supports a defined subset of OpenSSH authentication messages.
- IOC extraction does not perform reputation lookups or determine maliciousness.
