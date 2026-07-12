import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from soc_caseforge.reporting import render_json, render_markdown


class ReportingAndCLITests(unittest.TestCase):
    def test_renderers(self):
        snapshot = {
            "case": {"id": 1, "title": "Case", "analyst": "a", "status": "open", "created_at": "x", "updated_at": "x"},
            "events": [],
            "indicators": [],
            "findings": [],
            "limitations": ["limit"],
        }
        self.assertIn("Incident Case 1", render_markdown(snapshot))
        self.assertEqual(json.loads(render_json(snapshot))["case"]["id"], 1)

    def test_cli_workflow(self):
        with tempfile.TemporaryDirectory() as temp:
            temp_path = Path(temp)
            db = temp_path / "case.db"
            sample = temp_path / "sample.log"
            sample.write_text(
                "\n".join(
                    [
                        "Jul 12 08:00:01 lab sshd[1]: Failed password for root from 203.0.113.10 port 1 ssh2",
                        "Jul 12 08:00:02 lab sshd[2]: Failed password for admin from 203.0.113.10 port 1 ssh2",
                        "Jul 12 08:00:03 lab sshd[3]: Failed password for analyst from 203.0.113.10 port 1 ssh2",
                    ]
                ),
                encoding="utf-8",
            )
            base = [sys.executable, "-m", "soc_caseforge.cli", "--db", str(db)]
            subprocess.run(base + ["init"], check=True, capture_output=True, text=True)
            created = subprocess.run(
                base + ["new", "--title", "CLI case", "--analyst", "zaid"],
                check=True,
                capture_output=True,
                text=True,
            )
            case_id = json.loads(created.stdout)["case_id"]
            subprocess.run(base + ["ingest", str(case_id), str(sample)], check=True, capture_output=True, text=True)
            analyzed = subprocess.run(
                base + ["analyze", str(case_id), "--failed-threshold", "3", "--spray-threshold", "3"],
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertGreaterEqual(json.loads(analyzed.stdout)["findings"], 2)
            report = subprocess.run(base + ["report", str(case_id)], check=True, capture_output=True, text=True)
            self.assertIn("CLI case", report.stdout)

    def test_cli_invalid_case_exits_two(self):
        with tempfile.TemporaryDirectory() as temp:
            db = Path(temp) / "case.db"
            result = subprocess.run(
                [sys.executable, "-m", "soc_caseforge.cli", "--db", str(db), "report", "999"],
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 2)


class InstalledResourceShapeTests(unittest.TestCase):
    def test_bundled_demo_resource_exists(self):
        from importlib.resources import files
        resource = files("soc_caseforge.data").joinpath("openssh_demo.log")
        self.assertIn("Failed password", resource.read_text(encoding="utf-8"))
