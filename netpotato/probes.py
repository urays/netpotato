"""Probe collection and IP parsing."""

from __future__ import annotations

from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime
import html
import ipaddress
import re
import time
from typing import Optional
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen


DEFAULT_PROBE_URL = "https://ip111.cn/"
DEFAULT_SCAMALYTICS_URL_TEMPLATE = "https://scamalytics.com/ip/{ip}"
DIRECT_IP_CANDIDATE_URLS = (
    "https://4.ipw.cn",
    "https://myip.ipip.net",
    "https://api64.ipify.org",
    "https://icanhazip.com",
    "https://ifconfig.me/ip",
    "https://us.ip111.cn/ip.php",
    "https://sspanel.net/ip.php",
)

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
MAX_RESPONSE_BYTES = 1024 * 1024
FETCHABLE_URL_SCHEMES = {"http", "https"}

IP_TOKEN_RE = re.compile(r"[0-9A-Fa-f:.%]+")
HTML_TAG_RE = re.compile(r"(?s)<[^>]+>")
SCRIPT_STYLE_RE = re.compile(r"(?is)<(script|style).*?>.*?</\1>")
IFRAME_SRC_RE = re.compile(r'(?is)<iframe\b[^>]*\bsrc=["\']([^"\']+)["\']')
FRAUD_SCORE_RE = re.compile(r"Fraud Score:\s*(\d+)", re.IGNORECASE)
FRAUD_RISK_RE = re.compile(r"^(very high|high|medium|low|very low)\s+risk$", re.IGNORECASE)
LINE_PREFIXES = {
    "isp_name": "ISP Name ",
    "country_name": "Country Name ",
}
SCAMALYTICS_PROXY_LABELS = {
    "Anonymizing VPN": "is_anonymizing_vpn",
    "Tor Exit Node": "is_tor_exit_node",
    "Server": "is_server",
    "Public Proxy": "is_public_proxy",
    "Web Proxy": "is_web_proxy",
}
SCAMALYTICS_BLACKLIST_LABELS = (
    "Firehol",
    "IP2ProxyLite",
    "IPsum",
    "Spamhaus",
    "X4Bnet Spambot",
)


@dataclass
class IPQuality:
    ip: str
    risk: str
    score: Optional[int]
    source_url: str
    isp_name: Optional[str] = None
    country_name: Optional[str] = None
    is_blacklisted_external: Optional[bool] = None
    is_anonymizing_vpn: Optional[bool] = None
    is_tor_exit_node: Optional[bool] = None
    is_server: Optional[bool] = None
    is_public_proxy: Optional[bool] = None
    is_web_proxy: Optional[bool] = None


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
    ip_quality: Optional[IPQuality] = None
    ip_quality_error: Optional[str] = None

    def available_remote_ips(self) -> list[str]:
        return [ip for ip in (self.domestic, self.foreign, self.google) if ip]

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


def is_fetchable_url(url: str) -> bool:
    parsed = urlparse(url)
    return parsed.scheme in FETCHABLE_URL_SCHEMES and bool(parsed.netloc)


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


def parse_yes_no_unknown(value: str) -> Optional[bool]:
    normalized = value.strip().lower()
    if normalized == "yes":
        return True
    if normalized == "no":
        return False
    return None


def next_line_value(lines: list[str], index: int) -> Optional[str]:
    if index + 1 >= len(lines):
        return None
    return lines[index + 1]


def parse_scamalytics_quality(page_html: str, ip: str, source_url: str) -> IPQuality:
    lines = html_to_lines(page_html)
    score: Optional[int] = None
    risk = "unknown"
    isp_name: Optional[str] = None
    country_name: Optional[str] = None
    proxy_values: dict[str, Optional[bool]] = {}
    blacklist_flags: list[bool] = []

    for index, line in enumerate(lines):
        if score is None:
            score_match = FRAUD_SCORE_RE.search(line)
            if score_match:
                score = int(score_match.group(1))

        if risk == "unknown":
            risk_match = FRAUD_RISK_RE.match(line)
            if risk_match:
                risk = risk_match.group(1).lower()

        if isp_name is None and line.startswith(LINE_PREFIXES["isp_name"]):
            isp_name = line.removeprefix(LINE_PREFIXES["isp_name"]).strip() or None
        if country_name is None and line.startswith(LINE_PREFIXES["country_name"]):
            country_name = line.removeprefix(LINE_PREFIXES["country_name"]).strip() or None

        attr = SCAMALYTICS_PROXY_LABELS.get(line)
        if attr:
            proxy_values[attr] = parse_yes_no_unknown(next_line_value(lines, index) or "")
            continue

        if line in SCAMALYTICS_BLACKLIST_LABELS:
            parsed = parse_yes_no_unknown(next_line_value(lines, index) or "")
            if parsed is not None:
                blacklist_flags.append(parsed)

    return IPQuality(
        ip=ip,
        risk=risk,
        score=score,
        source_url=source_url,
        isp_name=isp_name,
        country_name=country_name,
        is_blacklisted_external=True if any(blacklist_flags) else False if blacklist_flags else None,
        is_anonymizing_vpn=proxy_values.get("is_anonymizing_vpn"),
        is_tor_exit_node=proxy_values.get("is_tor_exit_node"),
        is_server=proxy_values.get("is_server"),
        is_public_proxy=proxy_values.get("is_public_proxy"),
        is_web_proxy=proxy_values.get("is_web_proxy"),
    )


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
        candidate = urljoin(source_url, html.unescape(match.group(1)))
        if is_fetchable_url(candidate):
            sources[key] = candidate
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
    if not is_fetchable_url(url):
        raise ValueError(f"Unsupported probe URL: {url!r}")
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
                content_length_header = response.headers.get("Content-Length")
                if content_length_header:
                    try:
                        content_length = int(content_length_header)
                    except ValueError:
                        content_length = None
                    else:
                        if content_length > MAX_RESPONSE_BYTES:
                            raise ValueError(
                                f"Probe response exceeded {MAX_RESPONSE_BYTES} bytes."
                            )
                payload = response.read(MAX_RESPONSE_BYTES + 1)
                if len(payload) > MAX_RESPONSE_BYTES:
                    raise ValueError(
                        f"Probe response exceeded {MAX_RESPONSE_BYTES} bytes."
                    )
                return decode_response_bytes(payload, charset)
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
    return [url for url in dedupe_strings(candidates) if is_fetchable_url(url)]


def candidate_referers(probe_url: str) -> list[str | None]:
    valid_referers = [
        referer
        for referer in dedupe_strings([probe_url, DEFAULT_PROBE_URL])
        if is_fetchable_url(referer)
    ]
    return [*valid_referers, None]


def referer_label(referer: str | None) -> str:
    return referer or "<no referer>"


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
    referers = candidate_referers(probe_url)
    for url in candidate_urls:
        for referer in referers:
            try:
                ip = fetch_plain_ip(url, timeout, referer=referer)
                return ip, url, None
            except Exception as exc:  # noqa: BLE001
                errors.append(f"{url} via {referer_label(referer)}: {build_error_message(exc)}")

    return None, candidate_urls[0], "; ".join(errors)


def fetch_scamalytics_quality(ip: str, timeout: float) -> IPQuality:
    source_url = DEFAULT_SCAMALYTICS_URL_TEMPLATE.format(ip=ip)
    body = fetch_url_text(source_url, timeout, referer="https://scamalytics.com/ip")
    return parse_scamalytics_quality(body, ip, source_url)


def direct_ip_candidate_urls(probe_url: str) -> list[str]:
    preferred_url = probe_url if probe_url and probe_url != DEFAULT_PROBE_URL else ""
    return [
        url
        for url in dedupe_strings([preferred_url, *DIRECT_IP_CANDIDATE_URLS])
        if is_fetchable_url(url)
    ]


def fetch_domestic_ip(
    probe_url: str,
    timeout: float,
) -> tuple[Optional[str], str, Optional[str]]:
    candidate_urls = direct_ip_candidate_urls(probe_url)
    if not candidate_urls:
        return None, "", "no probe URL available"

    errors: list[str] = []
    referers = candidate_referers(probe_url)
    for url in candidate_urls:
        for referer in referers:
            try:
                ip = fetch_plain_ip(url, timeout, referer=referer)
                return ip, url, None
            except Exception as exc:  # noqa: BLE001
                errors.append(f"{url} via {referer_label(referer)}: {build_error_message(exc)}")

    return None, candidate_urls[0], "; ".join(errors)


def fetch_direct_ip_snapshot(probe_url: str, timeout: float) -> Snapshot:
    candidate_urls = direct_ip_candidate_urls(probe_url)
    if not candidate_urls:
        raise RuntimeError("Direct IP probe failed: no direct IP URL available.")

    errors: list[str] = []
    referers = candidate_referers(probe_url)
    for url in candidate_urls:
        for referer in referers:
            try:
                ip = fetch_plain_ip(url, timeout, referer=referer)
            except Exception as exc:  # noqa: BLE001
                errors.append(f"{url} via {referer_label(referer)}: {build_error_message(exc)}")
                continue

            snapshot = Snapshot(
                domestic=ip,
                foreign=None,
                google=None,
                fetched_at=now_iso(),
                source_url=url,
            )
            assign_section_result(snapshot, "domestic", ip, source=url)
            return snapshot

    raise RuntimeError(f"Direct IP probe failed: {'; '.join(errors)}")


def fetch_snapshot(
    probe_url: str,
    timeout: float,
    *,
    quality_enabled: bool = True,
    quality_ip_allow_partial: bool = False,
    prefer_direct_ip: bool = False,
) -> Snapshot:
    direct_error: str | None = None
    if prefer_direct_ip:
        # Pure IP-change mode tries direct public-IP probes first, then falls back to the HTML page if needed.
        try:
            snapshot = fetch_direct_ip_snapshot(probe_url, timeout)
        except Exception as exc:  # noqa: BLE001
            direct_error = str(exc)
        else:
            stable_ip = snapshot.domestic
            if quality_enabled and stable_ip:
                try:
                    snapshot.ip_quality = fetch_scamalytics_quality(stable_ip, timeout)
                except Exception as exc:  # noqa: BLE001
                    snapshot.ip_quality_error = build_error_message(exc)
            return snapshot

    try:
        body = fetch_url_text(probe_url, timeout)
    except Exception as exc:  # noqa: BLE001
        if direct_error is not None:
            error_message = build_error_message(exc)
            raise RuntimeError(f"{direct_error}; HTML probe fallback failed: {error_message}") from exc
        raise
    snapshot = parse_snapshot(body, probe_url)
    iframe_sources = discover_iframe_sources(body, probe_url)

    if not snapshot.domestic:
        ip, source, error = fetch_domestic_ip(probe_url, timeout)
        assign_section_result(snapshot, "domestic", ip, source=source, error=error)
    elif not snapshot.domestic_source:
        snapshot.domestic_source = probe_url

    missing_sections = [
        section for section in ("foreign", "google") if not getattr(snapshot, section)
    ]
    if missing_sections:
        with ThreadPoolExecutor(max_workers=len(missing_sections)) as executor:
            future_to_section = {
                executor.submit(fetch_section_ip, section, timeout, probe_url, iframe_sources): section
                for section in missing_sections
            }
            for future in as_completed(future_to_section):
                section = future_to_section[future]
                ip, source, error = future.result()
                assign_section_result(snapshot, section, ip, source=source, error=error)

    stable_ip = snapshot_consensus_ip(snapshot, allow_partial=quality_ip_allow_partial)
    if quality_enabled and stable_ip:
        try:
            snapshot.ip_quality = fetch_scamalytics_quality(stable_ip, timeout)
        except Exception as exc:  # noqa: BLE001
            snapshot.ip_quality_error = build_error_message(exc)

    return snapshot


def snapshot_summary(snapshot: Snapshot) -> str:
    values = [
        ("domestic", snapshot.domestic),
        ("overseas", snapshot.foreign),
        ("google", snapshot.google),
    ]
    summary = ", ".join(f"{name}={value or 'unavailable'}" for name, value in values)
    if snapshot.ip_quality:
        score = "?" if snapshot.ip_quality.score is None else snapshot.ip_quality.score
        summary = f"{summary}, quality={snapshot.ip_quality.risk}({score})"
    return summary


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


def snapshot_quality_reason(snapshot: Snapshot, config: object) -> Optional[str]:
    quality = snapshot.ip_quality
    if quality is None:
        return None

    reasons: list[str] = []
    score = quality.score
    threshold = getattr(config, "ip_quality_max_score")
    low_risk_band = quality.risk in {"low", "very low"} and (score is None or score < threshold)
    if low_risk_band:
        return None

    if score is not None and score >= threshold:
        reasons.append(
            f"Scamalytics reports IP {quality.ip} as {quality.risk} risk with fraud score {score}/100"
        )
    elif quality.risk in {"high", "very high"}:
        reasons.append(f"Scamalytics reports IP {quality.ip} as {quality.risk} risk")

    if getattr(config, "ip_quality_block_proxy"):
        proxy_flags: list[str] = []
        if quality.is_anonymizing_vpn:
            proxy_flags.append("anonymizing VPN")
        if quality.is_tor_exit_node:
            proxy_flags.append("Tor exit node")
        if quality.is_public_proxy:
            proxy_flags.append("public proxy")
        if quality.is_web_proxy:
            proxy_flags.append("web proxy")
        if quality.is_blacklisted_external:
            proxy_flags.append("external blacklist hit")
        if proxy_flags:
            reasons.append(
                f"Scamalytics flagged IP {quality.ip} as {'/'.join(proxy_flags)}"
            )

    if not reasons:
        return None

    if quality.isp_name or quality.country_name:
        context = ", ".join(
            value for value in (quality.isp_name, quality.country_name) if value
        )
        if context:
            reasons.append(f"provider context: {context}")

    return "; ".join(reasons)


def snapshot_consensus_ip(snapshot: Snapshot, *, allow_partial: bool = False) -> Optional[str]:
    values = [snapshot.domestic, snapshot.foreign, snapshot.google]
    available = [value for value in values if value]
    if not available:
        return None
    if not allow_partial:
        if len(available) != len(values):
            return None
        unique = {value for value in available}
        if len(unique) != 1:
            return None
        return next(iter(unique))

    counts = Counter(available)
    candidate, occurrences = counts.most_common(1)[0]
    if occurrences > len(available) / 2:
        return candidate
    return None
