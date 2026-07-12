from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable

from soc_caseforge.models import Event


FAILED_RE = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d\d:\d\d:\d\d).*?sshd\[\d+\]:\s+"
    r"Failed\s+(?P<method>password|publickey|keyboard-interactive/pam)\s+for\s+"
    r"(?:(?P<invalid>invalid user)\s+)?(?P<user>\S+)\s+from\s+(?P<ip>\S+)",
    re.IGNORECASE,
)
ACCEPTED_RE = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d\d:\d\d:\d\d).*?sshd\[\d+\]:\s+"
    r"Accepted\s+(?P<method>\S+)\s+for\s+(?P<user>\S+)\s+from\s+(?P<ip>\S+)",
    re.IGNORECASE,
)


def _normalize_ip(value: str) -> str | None:
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def parse_line(line: str) -> Event | None:
    match = FAILED_RE.search(line)
    if match:
        source_ip = _normalize_ip(match.group("ip"))
        if source_ip is None:
            return None
        return Event(
            source="openssh",
            category="authentication",
            action="login",
            outcome="failure",
            observed_at=match.group("timestamp"),
            source_ip=source_ip,
            user=match.group("user"),
            authentication_method=match.group("method").lower(),
            raw=line.rstrip("\n"),
            metadata={"invalid_user": match.group("invalid") is not None},
        )

    match = ACCEPTED_RE.search(line)
    if match:
        source_ip = _normalize_ip(match.group("ip"))
        if source_ip is None:
            return None
        return Event(
            source="openssh",
            category="authentication",
            action="login",
            outcome="success",
            observed_at=match.group("timestamp"),
            source_ip=source_ip,
            user=match.group("user"),
            authentication_method=match.group("method").lower(),
            raw=line.rstrip("\n"),
        )
    return None


def parse_lines(lines: Iterable[str]) -> list[Event]:
    return [event for line in lines if (event := parse_line(line)) is not None]
