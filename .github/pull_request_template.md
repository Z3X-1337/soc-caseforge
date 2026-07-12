## What changed

<!-- Summarize the behavior and files changed. -->

## Why

<!-- Describe the analyst problem, defect, or engineering requirement. -->

## Analyst impact

<!-- Explain how this changes ingestion, evidence, findings, storage, or reporting. -->

## Validation

- [ ] `python -m unittest discover -s tests -v`
- [ ] `python -m pip install .`
- [ ] `soc-caseforge --help`
- [ ] Added or updated tests for changed behavior
- [ ] Used sanitized evidence only

## Data and compatibility

- Stored-data schema changed: yes / no
- Report schema changed: yes / no
- Migration or compatibility notes:

## Detection and safety review

- New false-positive conditions:
- New limitations or unsupported cases:
- New trust boundaries or external services:
- Evidence and analyst-validation behavior:

## Documentation

- [ ] README or usage documentation updated when needed
- [ ] Architecture updated when components or data flow changed
- [ ] Threat model updated when a trust boundary changed
- [ ] Changelog updated for user-visible behavior
