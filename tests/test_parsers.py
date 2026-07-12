import unittest

from soc_caseforge.parsers.openssh import parse_line, parse_lines


class OpenSSHParserTests(unittest.TestCase):
    def test_parses_failed_password(self):
        event = parse_line("Jul 12 08:00:01 lab sshd[1]: Failed password for root from 203.0.113.10 port 1 ssh2")
        self.assertIsNotNone(event)
        self.assertEqual(event.outcome, "failure")
        self.assertEqual(event.source_ip, "203.0.113.10")
        self.assertEqual(event.authentication_method, "password")

    def test_parses_invalid_user(self):
        event = parse_line("Jul 12 08:00:01 lab sshd[1]: Failed password for invalid user admin from 203.0.113.10 port 1 ssh2")
        self.assertTrue(event.metadata["invalid_user"])
        self.assertEqual(event.user, "admin")

    def test_parses_ipv6(self):
        event = parse_line("Jul 12 08:00:01 lab sshd[1]: Failed publickey for root from 2001:db8::10 port 1 ssh2")
        self.assertEqual(event.source_ip, "2001:db8::10")

    def test_parses_success(self):
        event = parse_line("Jul 12 08:00:01 lab sshd[1]: Accepted publickey for root from 203.0.113.10 port 1 ssh2")
        self.assertEqual(event.outcome, "success")

    def test_ignores_unrelated_lines(self):
        self.assertIsNone(parse_line("cron unrelated"))
        self.assertEqual(parse_lines(["cron unrelated"]), [])

    def test_rejects_invalid_ip(self):
        self.assertIsNone(parse_line("Jul 12 08:00:01 lab sshd[1]: Failed password for root from not-an-ip port 1 ssh2"))
