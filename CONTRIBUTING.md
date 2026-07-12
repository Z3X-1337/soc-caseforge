# Contributing

SOC CaseForge accepts changes that improve defensive analyst workflows while preserving deterministic, local-first behavior.

## Before opening a change

- Use sanitized evidence only. Never submit production logs, credentials, tokens, customer data, or internal network inventories.
- Open or reference an issue for material parser, schema, detection, or report changes.
- Keep the proposed scope narrow enough to review and test independently.
- Describe expected false positives, missing context, and unsupported cases.

## Development setup

```bash
python -m venv .venv
source .venv/bin/activate  # Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install -e .
python -m unittest discover -s tests -v
```

## Engineering expectations

- Add tests for every parser, rule, schema, storage, or report change.
- Keep findings deterministic and explainable.
- Attach concrete evidence and limitations to new findings.
- Preserve local processing by default.
- Maintain backward compatibility or document the migration path.
- Update architecture and threat-model documentation when trust boundaries change.

## Pull requests

A pull request should state:

1. what changed;
2. why the change is needed;
3. expected analyst impact;
4. validation performed;
5. new limitations or false-positive conditions;
6. whether stored data or report schemas changed.

Run the complete validation set before requesting review:

```bash
python -m unittest discover -s tests -v
python -m pip install .
soc-caseforge --help
```

Changes that weaken authorization boundaries, upload evidence by default, or make unsupported claims about malicious intent will not be accepted.
