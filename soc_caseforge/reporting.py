from __future__ import annotations

import json
from typing import Any


def render_json(snapshot: dict[str, Any], pretty: bool = True) -> str:
    return json.dumps(snapshot, indent=2 if pretty else None, sort_keys=True)


def render_markdown(snapshot: dict[str, Any]) -> str:
    case = snapshot["case"]
    lines = [
        f"# Incident Case {case['id']}: {case['title']}",
        "",
        f"- Analyst: {case['analyst']}",
        f"- Status: {case['status']}",
        f"- Created: {case['created_at']}",
        f"- Updated: {case['updated_at']}",
        "",
        "## Executive Summary",
        "",
        f"The case contains {len(snapshot['events'])} parsed events, {len(snapshot['indicators'])} unique indicators, and {len(snapshot['findings'])} analyst-review findings.",
        "",
        "## Findings",
        "",
    ]

    if not snapshot["findings"]:
        lines.append("No configured heuristic produced a finding.")
    else:
        for finding in snapshot["findings"]:
            lines.extend(
                [
                    f"### [{finding['severity'].upper()}] {finding['title']}",
                    "",
                    finding["description"],
                    "",
                    f"- Rule: `{finding['rule_id']}`",
                    f"- Confidence: {finding['confidence']}",
                    f"- Evidence: {'; '.join(finding['evidence'])}",
                    f"- ATT&CK: {', '.join(item['id'] + ' ' + item['name'] for item in finding['attack_techniques']) or 'None'}",
                    "",
                    "Recommended actions:",
                    "",
                ]
            )
            lines.extend(f"- {action}" for action in finding["recommended_actions"])
            lines.append("")

    lines.extend(["## Timeline", ""])
    if not snapshot["events"]:
        lines.append("No parsed events.")
    else:
        lines.append("| Seq | Observed | Outcome | Source IP | User | Method |")
        lines.append("| ---: | --- | --- | --- | --- | --- |")
        for event in snapshot["events"]:
            lines.append(
                f"| {event['sequence']} | {event['observed_at'] or ''} | {event['outcome']} | "
                f"{event['source_ip'] or ''} | {event['user'] or ''} | {event['authentication_method'] or ''} |"
            )

    lines.extend(["", "## Indicators", ""])
    if not snapshot["indicators"]:
        lines.append("No indicators extracted.")
    else:
        lines.append("| Type | Value | Source form |")
        lines.append("| --- | --- | --- |")
        for indicator in snapshot["indicators"]:
            lines.append(f"| {indicator['type']} | `{indicator['value']}` | `{indicator['source_form']}` |")

    lines.extend(["", "## Limitations", ""])
    lines.extend(f"- {item}" for item in snapshot["limitations"])
    return "\n".join(lines)
