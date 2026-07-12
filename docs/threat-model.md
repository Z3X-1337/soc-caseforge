# Threat Model

## Protected assets

- Incident evidence.
- Analyst notes and case metadata.
- Local SQLite case database.

## Primary risks

- Accidental publication of sensitive evidence.
- Malformed input causing parser errors or misleading normalization.
- Over-trusting heuristic findings.
- Local unauthorized access to the SQLite database.

## Current controls

- Local-only processing with no telemetry or external requests.
- Parameterized SQLite queries.
- Explicit input parsing and IP validation.
- Deterministic findings with visible evidence and limitations.
- Sanitized demonstration data.

## Out of scope for v0.1.0

- Database encryption at rest.
- Multi-user access control.
- Malware detonation.
- Internet-wide scanning.
- Autonomous containment or remediation.
