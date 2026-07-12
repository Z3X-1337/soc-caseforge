import tempfile
import unittest
from pathlib import Path

from soc_caseforge.analysis import analyze_snapshot
from soc_caseforge.models import Event, Indicator
from soc_caseforge.storage import CaseStore


class StorageAndAnalysisTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = Path(self.temp.name) / "cases.db"
        self.store = CaseStore(self.db)
        self.store.initialize()
        self.case_id = self.store.create_case("Test case", "analyst")

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def _event(self, outcome, user="root", ip="203.0.113.10"):
        return Event("openssh", "authentication", "login", outcome, "Jul 12 08:00:01", ip, user, "password", "raw")

    def test_create_and_list_case(self):
        cases = self.store.list_cases()
        self.assertEqual(cases[0]["title"], "Test case")

    def test_rejects_empty_case_fields(self):
        with self.assertRaises(ValueError):
            self.store.create_case("", "analyst")

    def test_adds_events_and_indicators(self):
        self.assertEqual(self.store.add_events(self.case_id, [self._event("failure")]), 1)
        self.assertEqual(self.store.add_indicators(self.case_id, [Indicator("ipv4", "203.0.113.10", "203.0.113.10")]), 1)
        snapshot = self.store.case_snapshot(self.case_id)
        self.assertEqual(len(snapshot["events"]), 1)
        self.assertEqual(len(snapshot["indicators"]), 1)

    def test_indicator_uniqueness(self):
        indicator = Indicator("ipv4", "203.0.113.10", "203.0.113.10")
        self.assertEqual(self.store.add_indicators(self.case_id, [indicator]), 1)
        self.assertEqual(self.store.add_indicators(self.case_id, [indicator]), 0)

    def test_detects_repeated_failures(self):
        self.store.add_events(self.case_id, [self._event("failure") for _ in range(3)])
        findings = analyze_snapshot(self.store.case_snapshot(self.case_id), failed_threshold=3)
        self.assertTrue(any(item.rule_id.startswith("SSH-BRUTE") for item in findings))

    def test_detects_password_spray(self):
        events = [self._event("failure", user=user) for user in ("root", "admin", "analyst")]
        self.store.add_events(self.case_id, events)
        findings = analyze_snapshot(self.store.case_snapshot(self.case_id), failed_threshold=99, spray_threshold=3)
        self.assertTrue(any(item.rule_id.startswith("SSH-SPRAY") for item in findings))

    def test_detects_success_after_failures(self):
        self.store.add_events(self.case_id, [self._event("failure"), self._event("success")])
        findings = analyze_snapshot(self.store.case_snapshot(self.case_id), failed_threshold=99)
        self.assertTrue(any("SUCCESS-AFTER-FAILURE" in item.rule_id for item in findings))

    def test_validates_thresholds(self):
        with self.assertRaises(ValueError):
            analyze_snapshot(self.store.case_snapshot(self.case_id), failed_threshold=0)

    def test_replace_findings(self):
        self.store.add_events(self.case_id, [self._event("failure") for _ in range(3)])
        findings = analyze_snapshot(self.store.case_snapshot(self.case_id), failed_threshold=3)
        self.store.replace_findings(self.case_id, findings)
        self.assertEqual(len(self.store.case_snapshot(self.case_id)["findings"]), len(findings))
