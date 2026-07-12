# Architecture

## Components

- `parsers`: convert source-specific evidence into normalized events.
- `indicators`: extract and normalize common indicators from raw evidence.
- `storage`: persist cases, events, indicators, and findings in SQLite.
- `analysis`: apply deterministic rules to normalized events.
- `reporting`: render case snapshots as Markdown or JSON.
- `cli`: coordinate the workflow and expose stable exit behavior.

## Data flow

Evidence file → parser and IOC extractor → SQLite case store → deterministic analysis → analyst-review report.

## Design constraints

- Local-first operation.
- No external network calls.
- No runtime dependencies outside the Python standard library.
- Evidence, limitations, and recommended next actions are visible in reports.
- Parsers should fail closed by ignoring unsupported lines rather than inventing fields.
