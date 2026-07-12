from __future__ import annotations

import ipaddress
import re
import urllib.parse

from soc_caseforge.models import Indicator


URL_RE = re.compile(r"\bhttps?://[^\s<>\"']+", re.IGNORECASE)
EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,63}\b", re.IGNORECASE)
IP_CANDIDATE_RE = re.compile(r"(?<![\w:])(?:[0-9A-Fa-f:.]{3,})(?![\w:])")
HASH_PATTERNS = {
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
}
DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[A-Za-z]{2,63}\b")


def _trim_url(value: str) -> str:
    return value.rstrip(".,;:!?)\"]}")


def extract_indicators(text: str) -> list[Indicator]:
    results: dict[tuple[str, str], Indicator] = {}
    occupied_domains: set[str] = set()

    for match in URL_RE.finditer(text):
        source_form = _trim_url(match.group(0))
        parsed = urllib.parse.urlsplit(source_form)
        if not parsed.hostname:
            continue
        value = urllib.parse.urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), parsed.path, parsed.query, ""))
        results[("url", value)] = Indicator("url", value, source_form)
        occupied_domains.add(parsed.hostname.lower())

    for match in EMAIL_RE.finditer(text):
        source_form = match.group(0)
        local, domain = source_form.rsplit("@", 1)
        value = f"{local}@{domain.lower()}"
        results[("email", value)] = Indicator("email", value, source_form)
        occupied_domains.add(domain.lower())

    for match in IP_CANDIDATE_RE.finditer(text):
        source_form = match.group(0).strip(".,;:!?)\"]}")
        try:
            value = str(ipaddress.ip_address(source_form))
        except ValueError:
            continue
        indicator_type = "ipv4" if ":" not in value else "ipv6"
        results[(indicator_type, value)] = Indicator(indicator_type, value, source_form)

    for indicator_type, pattern in HASH_PATTERNS.items():
        for match in pattern.finditer(text):
            source_form = match.group(0)
            value = source_form.lower()
            results[(indicator_type, value)] = Indicator(indicator_type, value, source_form)

    for match in DOMAIN_RE.finditer(text):
        source_form = match.group(0)
        value = source_form.lower().rstrip(".")
        if value in occupied_domains:
            continue
        results[("domain", value)] = Indicator("domain", value, source_form)

    return sorted(results.values(), key=lambda item: (item.type, item.value))
