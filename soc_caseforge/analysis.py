from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any

from soc_caseforge.models import Finding


SEVERITY_ORDER = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def analyze_snapshot(
    snapshot: dict[str, Any],
    failed_threshold: int = 5,
    spray_threshold: int = 3,
) -> list[Finding]:
    if failed_threshold < 1 or spray_threshold < 1:
        raise ValueError("thresholds must be at least 1")

    failed_by_ip: Counter[str] = Counter()
    users_by_ip: dict[str, set[str]] = defaultdict(set)
    failures_before_success: dict[tuple[str, str], int] = defaultdict(int)
    successful_pairs: set[tuple[str, str]] = set()

    for event in snapshot["events"]:
        if event["category"] != "authentication" or not event.get("source_ip"):
            continue
        pair = (event["source_ip"], event.get("user") or "")
        if event["outcome"] == "failure":
            failed_by_ip[event["source_ip"]] += 1
            if event.get("user"):
                users_by_ip[event["source_ip"]].add(event["user"])
            failures_before_success[pair] += 1
        elif event["outcome"] == "success":
            successful_pairs.add(pair)

    findings: list[Finding] = []
    for source_ip, failed_count in failed_by_ip.items():
        targeted_users = sorted(users_by_ip[source_ip])
        if failed_count >= failed_threshold:
            severity = "high" if failed_count >= failed_threshold * 2 else "medium"
            findings.append(
                Finding(
                    rule_id=f"SSH-BRUTE-{source_ip}",
                    title=f"Repeated authentication failures from {source_ip}",
                    severity=severity,
                    confidence="high",
                    description="A single source exceeded the configured failed-authentication threshold.",
                    evidence=[
                        f"failed_attempts={failed_count}",
                        f"targeted_users={','.join(targeted_users) or 'unknown'}",
                        f"threshold={failed_threshold}",
                    ],
                    attack_techniques=[{"id": "T1110", "name": "Brute Force"}],
                    recommended_actions=[
                        "Validate whether the source is expected infrastructure.",
                        "Review adjacent authentication and network telemetry.",
                        "Consider temporary containment when the source is unauthorized.",
                    ],
                )
            )
        if len(targeted_users) >= spray_threshold:
            findings.append(
                Finding(
                    rule_id=f"SSH-SPRAY-{source_ip}",
                    title=f"Multiple usernames targeted from {source_ip}",
                    severity="high",
                    confidence="medium",
                    description="The source targeted multiple distinct usernames, consistent with a password-spray-style pattern.",
                    evidence=[
                        f"distinct_users={len(targeted_users)}",
                        f"users={','.join(targeted_users)}",
                        f"threshold={spray_threshold}",
                    ],
                    attack_techniques=[{"id": "T1110.003", "name": "Password Spraying"}],
                    recommended_actions=[
                        "Check whether the targeted accounts share exposure or naming patterns.",
                        "Review successful authentications involving the same source.",
                        "Validate MFA and account lockout telemetry where available.",
                    ],
                )
            )

    for source_ip, user in sorted(successful_pairs):
        failed_count = failures_before_success[(source_ip, user)]
        if failed_count:
            findings.append(
                Finding(
                    rule_id=f"SSH-SUCCESS-AFTER-FAILURE-{source_ip}-{user}",
                    title=f"Successful login after failures for {user}",
                    severity="high",
                    confidence="medium",
                    description="A successful authentication was observed after failed attempts from the same source and username.",
                    evidence=[f"source_ip={source_ip}", f"user={user}", f"prior_failures={failed_count}"],
                    attack_techniques=[{"id": "T1110", "name": "Brute Force"}],
                    recommended_actions=[
                        "Confirm the login with the account owner.",
                        "Review the authenticated session and post-login activity.",
                        "Reset credentials and contain the account if unauthorized.",
                    ],
                )
            )

    return sorted(
        findings,
        key=lambda item: (-SEVERITY_ORDER[item.severity], item.rule_id),
    )
