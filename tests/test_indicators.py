import unittest

from soc_caseforge.indicators import extract_indicators


class IndicatorTests(unittest.TestCase):
    def test_extracts_url_without_duplicate_domain(self):
        indicators = extract_indicators("Visit https://Example.com/path.")
        self.assertEqual([(item.type, item.value) for item in indicators], [("url", "https://example.com/path")])

    def test_extracts_email(self):
        indicators = extract_indicators("Contact Analyst@Example.COM")
        self.assertIn(("email", "Analyst@example.com"), [(item.type, item.value) for item in indicators])

    def test_extracts_ipv4_and_ipv6(self):
        indicators = extract_indicators("203.0.113.10 and 2001:db8::10")
        pairs = {(item.type, item.value) for item in indicators}
        self.assertIn(("ipv4", "203.0.113.10"), pairs)
        self.assertIn(("ipv6", "2001:db8::10"), pairs)

    def test_extracts_hashes(self):
        value = "a" * 64
        indicators = extract_indicators(value)
        self.assertEqual(indicators[0].type, "sha256")

    def test_deduplicates(self):
        indicators = extract_indicators("203.0.113.10 203.0.113.10")
        self.assertEqual(len(indicators), 1)
