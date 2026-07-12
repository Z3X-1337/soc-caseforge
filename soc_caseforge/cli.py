from __future__ import annotations

import argparse
import json
import sys
from importlib.resources import files
from pathlib import Path

from soc_caseforge.analysis import analyze_snapshot
from soc_caseforge.indicators import extract_indicators
from soc_caseforge.parsers.openssh import parse_lines
from soc_caseforge.reporting import render_json, render_markdown
from soc_caseforge.storage import CaseStore


def _store(path: Path) -> CaseStore:
    store = CaseStore(path)
    store.initialize()
    return store


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="soc-caseforge",
        description="Local-first SOC case workspace for sanitized analyst evidence.",
    )
    parser.add_argument("--db", type=Path, default=Path("caseforge.db"), help="SQLite case database.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("init", help="Initialize the local case database.")

    new_parser = subparsers.add_parser("new", help="Create a new incident case.")
    new_parser.add_argument("--title", required=True)
    new_parser.add_argument("--analyst", required=True)

    list_parser = subparsers.add_parser("list", help="List incident cases.")
    list_parser.add_argument("--pretty", action="store_true")

    ingest_parser = subparsers.add_parser("ingest", help="Ingest sanitized evidence into a case.")
    ingest_parser.add_argument("case_id", type=int)
    ingest_parser.add_argument("evidence_file", type=Path)
    ingest_parser.add_argument("--source", choices=("openssh", "text"), default="openssh")

    analyze_parser = subparsers.add_parser("analyze", help="Run deterministic case heuristics.")
    analyze_parser.add_argument("case_id", type=int)
    analyze_parser.add_argument("--failed-threshold", type=int, default=5)
    analyze_parser.add_argument("--spray-threshold", type=int, default=3)

    report_parser = subparsers.add_parser("report", help="Render a case report.")
    report_parser.add_argument("case_id", type=int)
    report_parser.add_argument("--format", choices=("markdown", "json"), default="markdown")
    report_parser.add_argument("--output", type=Path)
    report_parser.add_argument("--compact", action="store_true")

    demo_parser = subparsers.add_parser("demo", help="Create and analyze a case from the bundled sample.")
    demo_parser.add_argument("--analyst", default="demo-analyst")
    return parser


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise ValueError(f"unable to read {path}: {exc}") from exc


def _write_or_print(output: Path | None, content: str) -> None:
    if output:
        output.write_text(content + ("" if content.endswith("\n") else "\n"), encoding="utf-8")
    else:
        print(content)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        with _store(args.db) as store:
            if args.command == "init":
                print(json.dumps({"database": str(args.db), "initialized": True}))
                return 0

            if args.command == "new":
                case_id = store.create_case(args.title, args.analyst)
                print(json.dumps({"case_id": case_id, "title": args.title, "analyst": args.analyst}))
                return 0

            if args.command == "list":
                print(json.dumps(store.list_cases(), indent=2 if args.pretty else None, sort_keys=True))
                return 0

            if args.command == "ingest":
                text = _read_text(args.evidence_file)
                events = parse_lines(text.splitlines()) if args.source == "openssh" else []
                indicators = extract_indicators(text)
                event_count = store.add_events(args.case_id, events)
                indicator_count = store.add_indicators(args.case_id, indicators)
                print(json.dumps({"events_added": event_count, "indicators_added": indicator_count}))
                return 0

            if args.command == "analyze":
                snapshot = store.case_snapshot(args.case_id)
                findings = analyze_snapshot(
                    snapshot,
                    failed_threshold=args.failed_threshold,
                    spray_threshold=args.spray_threshold,
                )
                store.replace_findings(args.case_id, findings)
                print(json.dumps({"case_id": args.case_id, "findings": len(findings)}))
                return 0

            if args.command == "report":
                snapshot = store.case_snapshot(args.case_id)
                content = (
                    render_markdown(snapshot)
                    if args.format == "markdown"
                    else render_json(snapshot, pretty=not args.compact)
                )
                _write_or_print(args.output, content)
                return 0

            if args.command == "demo":
                sample = files("soc_caseforge.data").joinpath("openssh_demo.log")
                case_id = store.create_case("OpenSSH suspicious authentication demo", args.analyst)
                text = sample.read_text(encoding="utf-8")
                store.add_events(case_id, parse_lines(text.splitlines()))
                store.add_indicators(case_id, extract_indicators(text))
                snapshot = store.case_snapshot(case_id)
                store.replace_findings(case_id, analyze_snapshot(snapshot, failed_threshold=3, spray_threshold=3))
                print(render_markdown(store.case_snapshot(case_id)))
                return 0
    except (ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
