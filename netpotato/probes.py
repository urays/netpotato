"""Probe collection and IP parsing."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import html
import ipaddress
import re
import time
from typing import Optional
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin
from urllib.request import Request, urlopen


DEFAULT_PROBE_URL = "https://ip111.cn/"

SECTION_LABELS = {
    "domestic": "从国内测试",
    "foreign": "从国外测试",
    "google": "从谷歌测试",
}

KNOWN_SECTION_URLS = {
    "foreign": ("https://us.ip111.cn/ip.php",),
    "google": ("https://sspanel.net/ip.php",),
}
RETRY_DELAYS_SEC = (0.25, 0.6)

IP_TOKEN_RE = re.compile(r"[0-9A-Fa-f:.%]+")
HTML_TAG_RE = re.compile(r"(?s)<[^>]+>")
SCRIPT_STYLE_RE = re.compile(r"(?is)<(script|style).*?>.*?</\1>")
IFRAME_SRC_RE = re.compile(r'(?is)<iframe\b[^>]*\bsrc=["\']([^"\']+)["\']')


@dataclass
class Snapshot:
    domestic: Optional[str]
    foreign: Optional[str]
    google: Optional[str]
    fetched_at: str
    source_url: str
    domestic_source: str = ""
    domestic_error: Optional[str] = None
    foreign_source: str = ""
    foreign_error: Optional[str] = None
    google_source: str = ""
    google_error: Optional[str] = None

    def available_remote_ips(self) -> list[str]:
        return [ip for ip in (self.domestic, self.foreign, self.google) if ip]

    def missing_points(self) -> list[str]:
        missing: list[str] = []
        if not self.domestic:
            missing.append("Domestic")
        if not self.foreign:
            missing.append("Overseas")
        if not self.google:
            missing.append("Google")
        return missing

    def is_remote_mismatch(self) -> bool:
        return len(set(self.available_remote_ips())) > 1


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def build_error_message(exc: Exception) -> str:
    if isinstance(exc, HTTPError):
        return f"HTTP error: {exc.code}"
    if isinstance(exc, URLError):
        return f"Network error: {exc.reason}"
    return str(exc)


def normalize_whitespace(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def _section_source_attr(section: str) -> str:
    return f"{section}_source"


def _section_error_attr(section: str) -> str:
    return f"{section}_error"


def assign_section_result(
    snapshot: Snapshot,
    section: str,
    ip: Optional[str],
    *,
    source: str = "",
    error: Optional[str] = None,
) -> None:
    setattr(snapshot, section, ip)
    setattr(snapshot, _section_source_attr(section), source)
    setattr(snapshot, _section_error_attr(section), error)


def extract_ip_from_line(line: str) -> Optional[str]:
    for token in IP_TOKEN_RE.findall(line):
        candidate = token.strip("[](){}<>,;")
        if not candidate:
            continue
        base_candidate = candidate.split("%", 1)[0]
        try:
            ipaddress.ip_address(base_candidate)
        except ValueError:
            continue
        return base_candidate
    return None


def html_to_lines(page_html: str) -> list[str]:
    without_scripts = SCRIPT_STYLE_RE.sub(" ", page_html)
    text = HTML_TAG_RE.sub("\n", without_scripts)
    text = html.unescape(text).replace("\xa0", " ")
    lines: list[str] = []
    for raw_line in text.splitlines():
        line = normalize_whitespace(raw_line)
        if line:
            lines.append(line)
    return lines


def parse_snapshot(page_html: str, source_url: str) -> Snapshot:
    lines = html_to_lines(page_html)
    label_indexes: dict[str, int] = {}

    for index, line in enumerate(lines):
        for key, label in SECTION_LABELS.items():
            if label in line and key not in label_indexes:
                label_indexes[key] = index

    values: dict[str, Optional[str]] = {}
    for key in SECTION_LABELS:
        start = label_indexes.get(key)
        if start is None:
            values[key] = None
            continue

        next_indexes = [idx for idx in label_indexes.values() if idx > start]
        end = min(next_indexes) if next_indexes else len(lines)
        found_ip = None
        for line in lines[start:end]:
            found_ip = extract_ip_from_line(line)
            if found_ip:
                break
        values[key] = found_ip

    if not any(values.values()):
        fallback_ips: list[str] = []
        for line in lines:
            ip = extract_ip_from_line(line)
            if ip:
                fallback_ips.append(ip)
            if len(fallback_ips) >= 3:
                break
        if len(fallback_ips) >= 3:
            values = {
                "domestic": fallback_ips[0],
                "foreign": fallback_ips[1],
                "google": fallback_ips[2],
            }
        else:
            values = {
                "domestic": None,
                "foreign": None,
                "google": None,
            }

    snapshot = Snapshot(
        domestic=values.get("domestic"),
        foreign=values.get("foreign"),
        google=values.get("google"),
        fetched_at=now_iso(),
        source_url=source_url,
    )
    for key in SECTION_LABELS:
        value = values.get(key)
        if value:
            assign_section_result(snapshot, key, value, source=source_url)
    return snapshot


def extract_section_fragments(page_html: str) -> dict[str, str]:
    positions: list[tuple[int, str]] = []
    for key, label in SECTION_LABELS.items():
        index = page_html.find(label)
        if index >= 0:
            positions.append((index, key))

    positions.sort()
    fragments: dict[str, str] = {}
    for offset, (start, key) in enumerate(positions):
        end = positions[offset + 1][0] if offset + 1 < len(positions) else len(page_html)
        fragments[key] = page_html[start:end]
    return fragments


def discover_iframe_sources(page_html: str, source_url: str) -> dict[str, str]:
    fragments = extract_section_fragments(page_html)
    sources: dict[str, str] = {}
    for key, fragment in fragments.items():
        match = IFRAME_SRC_RE.search(fragment)
        if not match:
            continue
        sources[key] = urljoin(source_url, html.unescape(match.group(1)))
    return sources


def dedupe_strings(values: list[str]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        if not value or value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def decode_response_bytes(data: bytes, charset: str | None) -> str:
    encodings = dedupe_strings([charset or "", "utf-8", "gb18030", "latin-1"])
    for encoding in encodings:
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="ignore")


def fetch_url_text(url: str, timeout: float, referer: str | None = None) -> str:
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (X11; Linux x86_64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/122.0.0.0 Safari/537.36"
        ),
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }
    if referer:
        headers["Referer"] = referer

    last_error: Exception | None = None
    for attempt in range(len(RETRY_DELAYS_SEC) + 1):
        request = Request(url, headers=headers)
        try:
            with urlopen(request, timeout=timeout) as response:
                charset = response.headers.get_content_charset()
                return decode_response_bytes(response.read(), charset)
        except Exception as exc:  # noqa: BLE001
            last_error = exc
            if attempt >= len(RETRY_DELAYS_SEC):
                raise
            time.sleep(RETRY_DELAYS_SEC[attempt])

    if last_error is not None:
        raise last_error
    raise RuntimeError(f"Failed to fetch {url}")


def fetch_plain_ip(url: str, timeout: float, referer: str | None = None) -> str:
    body = fetch_url_text(url, timeout, referer=referer)
    ip = extract_ip_from_line(body)
    if not ip:
        raise ValueError(f"Could not extract an IP address from the response returned by {url}.")
    return ip


def section_candidate_urls(section: str, iframe_sources: dict[str, str]) -> list[str]:
    candidates: list[str] = []
    iframe_url = iframe_sources.get(section)
    if iframe_url:
        candidates.append(iframe_url)
    candidates.extend(KNOWN_SECTION_URLS.get(section, ()))
    return dedupe_strings(candidates)


def fetch_section_ip(
    section: str,
    timeout: float,
    probe_url: str,
    iframe_sources: dict[str, str],
) -> tuple[Optional[str], str, Optional[str]]:
    candidate_urls = section_candidate_urls(section, iframe_sources)
    if not candidate_urls:
        return None, "", "no probe URL available"

    errors: list[str] = []
    referers = dedupe_strings([probe_url, DEFAULT_PROBE_URL])
    for url in candidate_urls:
        for referer in referers:
            try:
                ip = fetch_plain_ip(url, timeout, referer=referer)
                return ip, url, None
            except Exception as exc:  # noqa: BLE001
                errors.append(f"{url} via {referer}: {build_error_message(exc)}")

    return None, candidate_urls[0], "; ".join(errors)


def fetch_snapshot(probe_url: str, timeout: float) -> Snapshot:
    body = fetch_url_text(probe_url, timeout)
    snapshot = parse_snapshot(body, probe_url)
    iframe_sources = discover_iframe_sources(body, probe_url)

    if not snapshot.domestic and not snapshot.domestic_source:
        snapshot.domestic_source = probe_url

    for section in ("foreign", "google"):
        if getattr(snapshot, section):
            continue
        ip, source, error = fetch_section_ip(section, timeout, probe_url, iframe_sources)
        assign_section_result(snapshot, section, ip, source=source, error=error)

    return snapshot


def snapshot_summary(snapshot: Snapshot) -> str:
    values = [
        ("domestic", snapshot.domestic),
        ("overseas", snapshot.foreign),
        ("google", snapshot.google),
    ]
    return ", ".join(f"{name}={value or 'unavailable'}" for name, value in values)


def snapshot_diagnostics(snapshot: Snapshot) -> list[str]:
    diagnostics: list[str] = []
    for section in ("domestic", "foreign", "google"):
        value = getattr(snapshot, section)
        error = getattr(snapshot, _section_error_attr(section), None)
        source = getattr(snapshot, _section_source_attr(section), "")
        if value:
            continue
        if error and source:
            diagnostics.append(f"{section}: {error}")
            continue
        if error:
            diagnostics.append(f"{section}: {error}")
            continue
        if source:
            diagnostics.append(f"{section}: probe returned no IP from {source}")
            continue
        diagnostics.append(f"{section}: probe returned no IP")
    return diagnostics


def snapshot_baseline_ip(snapshot: Snapshot) -> Optional[str]:
    values = [snapshot.domestic, snapshot.foreign, snapshot.google]
    if any(not value for value in values):
        return None
    unique = {value for value in values if value}
    if len(unique) != 1:
        return None
    return next(iter(unique))
