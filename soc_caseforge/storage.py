from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from soc_caseforge.models import Event, Finding, Indicator


SCHEMA = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS cases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    analyst TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    sequence INTEGER NOT NULL,
    source TEXT NOT NULL,
    category TEXT NOT NULL,
    action TEXT NOT NULL,
    outcome TEXT NOT NULL,
    observed_at TEXT,
    source_ip TEXT,
    user TEXT,
    authentication_method TEXT,
    raw TEXT NOT NULL,
    metadata_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS indicators (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    type TEXT NOT NULL,
    value TEXT NOT NULL,
    source_form TEXT NOT NULL,
    UNIQUE(case_id, type, value)
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    rule_id TEXT NOT NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence TEXT NOT NULL,
    description TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    attack_json TEXT NOT NULL,
    actions_json TEXT NOT NULL,
    UNIQUE(case_id, rule_id, title)
);
"""


class CaseStore:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.connection = sqlite3.connect(self.path)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys = ON")

    def __enter__(self) -> "CaseStore":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def close(self) -> None:
        self.connection.close()

    def initialize(self) -> None:
        self.connection.executescript(SCHEMA)
        self.connection.commit()

    def create_case(self, title: str, analyst: str) -> int:
        title = title.strip()
        analyst = analyst.strip()
        if not title or not analyst:
            raise ValueError("title and analyst are required")
        cursor = self.connection.execute(
            "INSERT INTO cases (title, analyst) VALUES (?, ?)", (title, analyst)
        )
        self.connection.commit()
        return int(cursor.lastrowid)

    def require_case(self, case_id: int) -> sqlite3.Row:
        row = self.connection.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone()
        if row is None:
            raise ValueError(f"case {case_id} does not exist")
        return row

    def list_cases(self) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            "SELECT id, title, analyst, status, created_at, updated_at FROM cases ORDER BY id"
        ).fetchall()
        return [dict(row) for row in rows]

    def add_events(self, case_id: int, events: list[Event]) -> int:
        self.require_case(case_id)
        current = self.connection.execute(
            "SELECT COALESCE(MAX(sequence), 0) FROM events WHERE case_id = ?", (case_id,)
        ).fetchone()[0]
        for offset, event in enumerate(events, start=1):
            self.connection.execute(
                """INSERT INTO events (
                    case_id, sequence, source, category, action, outcome, observed_at,
                    source_ip, user, authentication_method, raw, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    case_id,
                    current + offset,
                    event.source,
                    event.category,
                    event.action,
                    event.outcome,
                    event.observed_at,
                    event.source_ip,
                    event.user,
                    event.authentication_method,
                    event.raw,
                    json.dumps(event.metadata, sort_keys=True),
                ),
            )
        self.connection.execute("UPDATE cases SET updated_at = CURRENT_TIMESTAMP WHERE id = ?", (case_id,))
        self.connection.commit()
        return len(events)

    def add_indicators(self, case_id: int, indicators: list[Indicator]) -> int:
        self.require_case(case_id)
        before = self.connection.total_changes
        for indicator in indicators:
            self.connection.execute(
                "INSERT OR IGNORE INTO indicators (case_id, type, value, source_form) VALUES (?, ?, ?, ?)",
                (case_id, indicator.type, indicator.value, indicator.source_form),
            )
        self.connection.commit()
        return self.connection.total_changes - before

    def replace_findings(self, case_id: int, findings: list[Finding]) -> None:
        self.require_case(case_id)
        self.connection.execute("DELETE FROM findings WHERE case_id = ?", (case_id,))
        for finding in findings:
            self.connection.execute(
                """INSERT INTO findings (
                    case_id, rule_id, title, severity, confidence, description,
                    evidence_json, attack_json, actions_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    case_id,
                    finding.rule_id,
                    finding.title,
                    finding.severity,
                    finding.confidence,
                    finding.description,
                    json.dumps(finding.evidence),
                    json.dumps(finding.attack_techniques),
                    json.dumps(finding.recommended_actions),
                ),
            )
        self.connection.commit()

    def case_snapshot(self, case_id: int) -> dict[str, Any]:
        case = dict(self.require_case(case_id))
        event_rows = self.connection.execute(
            "SELECT * FROM events WHERE case_id = ? ORDER BY sequence", (case_id,)
        ).fetchall()
        indicator_rows = self.connection.execute(
            "SELECT type, value, source_form FROM indicators WHERE case_id = ? ORDER BY type, value", (case_id,)
        ).fetchall()
        finding_rows = self.connection.execute(
            "SELECT * FROM findings WHERE case_id = ? ORDER BY severity DESC, rule_id", (case_id,)
        ).fetchall()

        events = []
        for row in event_rows:
            item = dict(row)
            item.pop("id")
            item.pop("case_id")
            item["metadata"] = json.loads(item.pop("metadata_json"))
            events.append(item)

        findings = []
        for row in finding_rows:
            item = dict(row)
            item.pop("id")
            item.pop("case_id")
            item["evidence"] = json.loads(item.pop("evidence_json"))
            item["attack_techniques"] = json.loads(item.pop("attack_json"))
            item["recommended_actions"] = json.loads(item.pop("actions_json"))
            findings.append(item)

        return {
            "schema_version": "0.1",
            "case": case,
            "events": events,
            "indicators": [dict(row) for row in indicator_rows],
            "findings": findings,
            "limitations": [
                "OpenSSH timestamps do not include a year or timezone and are retained as raw evidence.",
                "Detections are deterministic heuristics and require analyst validation.",
                "Indicator extraction does not determine maliciousness or reputation.",
            ],
        }
