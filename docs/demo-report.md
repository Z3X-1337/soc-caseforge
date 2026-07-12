# Incident Case 1: OpenSSH suspicious authentication demo

- Analyst: demo-analyst
- Status: open
- Created: 2026-07-12 09:26:41
- Updated: 2026-07-12 09:26:41

## Executive Summary

The case contains 6 parsed events, 2 unique indicators, and 3 analyst-review findings.

## Findings

### [MEDIUM] Repeated authentication failures from 203.0.113.10

A single source exceeded the configured failed-authentication threshold.

- Rule: `SSH-BRUTE-203.0.113.10`
- Confidence: high
- Evidence: failed_attempts=4; targeted_users=admin,analyst,root; threshold=3
- ATT&CK: T1110 Brute Force

Recommended actions:

- Validate whether the source is expected infrastructure.
- Review adjacent authentication and network telemetry.
- Consider temporary containment when the source is unauthorized.

### [HIGH] Multiple usernames targeted from 203.0.113.10

The source targeted multiple distinct usernames, consistent with a password-spray-style pattern.

- Rule: `SSH-SPRAY-203.0.113.10`
- Confidence: medium
- Evidence: distinct_users=3; users=admin,analyst,root; threshold=3
- ATT&CK: T1110.003 Password Spraying

Recommended actions:

- Check whether the targeted accounts share exposure or naming patterns.
- Review successful authentications involving the same source.
- Validate MFA and account lockout telemetry where available.

### [HIGH] Successful login after failures for analyst

A successful authentication was observed after failed attempts from the same source and username.

- Rule: `SSH-SUCCESS-AFTER-FAILURE-203.0.113.10-analyst`
- Confidence: medium
- Evidence: source_ip=203.0.113.10; user=analyst; prior_failures=2
- ATT&CK: T1110 Brute Force

Recommended actions:

- Confirm the login with the account owner.
- Review the authenticated session and post-login activity.
- Reset credentials and contain the account if unauthorized.

## Timeline

| Seq | Observed | Outcome | Source IP | User | Method |
| ---: | --- | --- | --- | --- | --- |
| 1 | Jul 12 08:00:01 | failure | 203.0.113.10 | admin | password |
| 2 | Jul 12 08:00:05 | failure | 203.0.113.10 | root | password |
| 3 | Jul 12 08:00:10 | failure | 203.0.113.10 | analyst | publickey |
| 4 | Jul 12 08:00:15 | failure | 203.0.113.10 | analyst | password |
| 5 | Jul 12 08:00:20 | success | 203.0.113.10 | analyst | password |
| 6 | Jul 12 08:01:00 | success | 198.51.100.25 | backup | publickey |

## Indicators

| Type | Value | Source form |
| --- | --- | --- |
| ipv4 | `198.51.100.25` | `198.51.100.25` |
| ipv4 | `203.0.113.10` | `203.0.113.10` |

## Limitations

- OpenSSH timestamps do not include a year or timezone and are retained as raw evidence.
- Detections are deterministic heuristics and require analyst validation.
- Indicator extraction does not determine maliciousness or reputation.

---

This report is generated from the repository's sanitized demonstration data. The IP addresses use documentation ranges and do not represent real infrastructure.
