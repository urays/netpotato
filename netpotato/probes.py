"""Probe collection and IP parsing."""

from __future__ import annotations

from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime
import html
import ipaddress
import re
from threading import Lock
import time
from typing import Optional
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen


DEFAULT_PROBE_URL = "https://ip111.cn/"
DEFAULT_SCAMALYTICS_URL_TEMPLATE = "https://scamalytics.com/ip/{ip}"
DIRECT_IP_PROVIDER_ENDPOINTS = (
    ("ipw-cn", "https://4.ipw.cn"),
    ("ipip-net", "https://myip.ipip.net"),
    ("ipify", "https://api64.ipify.org"),
    ("icanhazip", "https://icanhazip.com"),
    ("ifconfig-me", "https://ifconfig.me/ip"),
)
SECTION_DIRECT_PROVIDER_ENDPOINTS = {
    "foreign": (("ip111-us", "https://us.ip111.cn/ip.php"),),
    "google": (("sspanel-google", "https://sspanel.net/ip.php"),),
}

SECTION_LABELS = {
    "domestic": "从国内测试",
    "foreign": "从国外测试",
    "google": "从谷歌测试",
}
RETRY_DELAYS_SEC = (0.25, 0.6)
MAX_RESPONSE_BYTES = 1024 * 1024
FETCHABLE_URL_SCHEMES = {"http", "https"}
MIN_TIMEOUT_SLICE_SEC = 0.1
PROVIDER_CIRCUIT_FAILURE_THRESHOLD = 2
PROVIDER_CIRCUIT_RESET_SEC = 30.0

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

    def available_mismatch_ips(self) -> list[str]:
        return [ip for ip in (self.foreign, self.google) if ip]

    def is_remote_mismatch(self) -> bool:
        return len(set(self.available_mismatch_ips())) > 1


@dataclass(frozen=True)
class ProviderEndpoint:
    url: str
    referers: tuple[str | None, ...] = (None,)
    include_probe_referers: bool = False


@dataclass(frozen=True)
class ProbeProvider:
    name: str
    endpoints: tuple[ProviderEndpoint, ...]
    failure_threshold: int = PROVIDER_CIRCUIT_FAILURE_THRESHOLD
    reset_sec: float = PROVIDER_CIRCUIT_RESET_SEC


@dataclass
class ProviderCircuitState:
    failure_count: int = 0
    opened_until: float = 0.0


_PROVIDER_CIRCUITS: dict[str, ProviderCircuitState] = {}
_PROVIDER_CIRCUITS_LOCK = Lock()


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


def dedupe_referers(values: list[str | None]) -> list[str | None]:
    result: list[str | None] = []
    seen: set[str | None] = set()
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def reset_provider_circuits() -> None:
    with _PROVIDER_CIRCUITS_LOCK:
        _PROVIDER_CIRCUITS.clear()


def provider_circuit_open(provider: ProbeProvider) -> bool:
    with _PROVIDER_CIRCUITS_LOCK:
        state = _PROVIDER_CIRCUITS.get(provider.name)
        return bool(state and state.opened_until > time.monotonic())


def mark_provider_success(provider: ProbeProvider) -> None:
    with _PROVIDER_CIRCUITS_LOCK:
        _PROVIDER_CIRCUITS.pop(provider.name, None)


def mark_provider_failure(provider: ProbeProvider) -> None:
    with _PROVIDER_CIRCUITS_LOCK:
        state = _PROVIDER_CIRCUITS.setdefault(provider.name, ProviderCircuitState())
        state.failure_count += 1
        if state.failure_count >= provider.failure_threshold:
            state.opened_until = time.monotonic() + provider.reset_sec


def provider_skip_reason(provider: ProbeProvider) -> str:
    with _PROVIDER_CIRCUITS_LOCK:
        state = _PROVIDER_CIRCUITS.get(provider.name)
        if state is None or state.opened_until <= time.monotonic():
            return "available"
        remaining = max(0.0, state.opened_until - time.monotonic())
    return f"provider temporarily skipped by circuit breaker ({remaining:.1f}s remaining)"


def decode_response_bytes(data: bytes, charset: str | None) -> str:
    encodings = dedupe_strings([charset or "", "utf-8", "gb18030", "latin-1"])
    for encoding in encodings:
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="ignore")


def probe_deadline(timeout: float) -> float:
    return time.monotonic() + max(timeout, MIN_TIMEOUT_SLICE_SEC)


def remaining_timeout(timeout: float, deadline: float | None, context: str) -> float:
    if deadline is None:
        return timeout
    remaining = deadline - time.monotonic()
    if remaining < MIN_TIMEOUT_SLICE_SEC:
        raise TimeoutError(f"Probe time budget exhausted before {context}.")
    return min(timeout, remaining)


def bounded_retry_sleep(delay: float, deadline: float | None) -> None:
    if deadline is None:
        time.sleep(delay)
        return
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("Probe time budget exhausted during retry backoff.")
    time.sleep(min(delay, remaining))


def fetch_url_text(
    url: str,
    timeout: float,
    referer: str | None = None,
    *,
    deadline: float | None = None,
) -> str:
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
            request_timeout = remaining_timeout(timeout, deadline, f"fetching {url}")
            with urlopen(request, timeout=request_timeout) as response:
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
            bounded_retry_sleep(RETRY_DELAYS_SEC[attempt], deadline)

    if last_error is not None:
        raise last_error
    raise RuntimeError(f"Failed to fetch {url}")


def fetch_plain_ip(
    url: str,
    timeout: float,
    referer: str | None = None,
    *,
    deadline: float | None = None,
) -> str:
    body = fetch_url_text(url, timeout, referer=referer, deadline=deadline)
    ip = extract_ip_from_line(body)
    if not ip:
        raise ValueError(f"Could not extract an IP address from the response returned by {url}.")
    return ip


def candidate_referers(probe_url: str) -> list[str | None]:
    valid_referers = [
        referer
        for referer in dedupe_strings([probe_url, DEFAULT_PROBE_URL])
        if is_fetchable_url(referer)
    ]
    return [*valid_referers, None]


def referer_label(referer: str | None) -> str:
    return referer or "<no referer>"


def domestic_direct_providers(probe_url: str) -> tuple[ProbeProvider, ...]:
    providers: list[ProbeProvider] = []
    if probe_url and probe_url != DEFAULT_PROBE_URL and is_fetchable_url(probe_url):
        providers.append(
            ProbeProvider(
                name="custom-direct-probe",
                endpoints=(ProviderEndpoint(probe_url, include_probe_referers=True),),
            )
        )
    providers.extend(
        ProbeProvider(name=name, endpoints=(ProviderEndpoint(url),))
        for name, url in DIRECT_IP_PROVIDER_ENDPOINTS
    )
    return tuple(providers)


def section_direct_providers(
    section: str,
    iframe_sources: dict[str, str],
) -> tuple[ProbeProvider, ...]:
    providers: list[ProbeProvider] = []
    iframe_url = iframe_sources.get(section)
    if iframe_url and is_fetchable_url(iframe_url):
        providers.append(
            ProbeProvider(
                name=f"{section}-iframe",
                endpoints=(ProviderEndpoint(iframe_url, include_probe_referers=True),),
            )
        )
    providers.extend(
        ProbeProvider(
            name=name,
            endpoints=(ProviderEndpoint(url, include_probe_referers=True),),
        )
        for name, url in SECTION_DIRECT_PROVIDER_ENDPOINTS.get(section, ())
    )
    return tuple(providers)


def html_snapshot_providers(probe_url: str) -> tuple[ProbeProvider, ...]:
    providers: list[ProbeProvider] = []
    if is_fetchable_url(probe_url):
        providers.append(
            ProbeProvider(
                name="custom-html-probe" if probe_url != DEFAULT_PROBE_URL else "ip111-html",
                endpoints=(ProviderEndpoint(probe_url),),
            )
        )
    if probe_url != DEFAULT_PROBE_URL:
        providers.append(
            ProbeProvider(
                name="ip111-html",
                endpoints=(ProviderEndpoint(DEFAULT_PROBE_URL),),
            )
        )
    return tuple(providers)


def quality_providers(ip: str) -> tuple[ProbeProvider, ...]:
    return (
        ProbeProvider(
            name="scamalytics",
            endpoints=(
                ProviderEndpoint(
                    DEFAULT_SCAMALYTICS_URL_TEMPLATE.format(ip=ip),
                    referers=("https://scamalytics.com/ip",),
                ),
            ),
        ),
    )


def provider_endpoint_referers(endpoint: ProviderEndpoint, probe_url: str) -> list[str | None]:
    referers = list(endpoint.referers)
    if endpoint.include_probe_referers:
        referers = [*candidate_referers(probe_url), *referers]
    return dedupe_referers(referers or [None])


def fetch_plain_ip_from_providers(
    providers: tuple[ProbeProvider, ...],
    timeout: float,
    probe_url: str,
    *,
    deadline: float | None = None,
) -> tuple[Optional[str], str, Optional[str]]:
    if not providers:
        return None, "", "no provider available"

    errors: list[str] = []
    first_source = providers[0].endpoints[0].url if providers[0].endpoints else ""
    for provider in providers:
        if provider_circuit_open(provider):
            errors.append(f"{provider.name}: {provider_skip_reason(provider)}")
            continue

        provider_errors: list[str] = []
        for endpoint in provider.endpoints:
            first_source = first_source or endpoint.url
            for referer in provider_endpoint_referers(endpoint, probe_url):
                try:
                    ip = fetch_plain_ip(endpoint.url, timeout, referer=referer, deadline=deadline)
                except Exception as exc:  # noqa: BLE001
                    provider_errors.append(
                        f"{endpoint.url} via {referer_label(referer)}: {build_error_message(exc)}"
                    )
                    continue
                mark_provider_success(provider)
                return ip, endpoint.url, None

        mark_provider_failure(provider)
        errors.append(f"{provider.name}: {'; '.join(provider_errors)}")

    return None, first_source, "; ".join(errors)


def fetch_snapshot_from_html_providers(
    providers: tuple[ProbeProvider, ...],
    timeout: float,
    probe_url: str,
    *,
    deadline: float | None = None,
) -> tuple[Snapshot, dict[str, str]]:
    if not providers:
        raise RuntimeError("no HTML probe provider available")

    errors: list[str] = []
    for provider in providers:
        if provider_circuit_open(provider):
            errors.append(f"{provider.name}: {provider_skip_reason(provider)}")
            continue

        provider_errors: list[str] = []
        for endpoint in provider.endpoints:
            for referer in provider_endpoint_referers(endpoint, probe_url):
                try:
                    body = fetch_url_text(
                        endpoint.url,
                        timeout,
                        referer=referer,
                        deadline=deadline,
                    )
                except Exception as exc:  # noqa: BLE001
                    provider_errors.append(
                        f"{endpoint.url} via {referer_label(referer)}: {build_error_message(exc)}"
                    )
                    continue

                mark_provider_success(provider)
                return parse_snapshot(body, endpoint.url), discover_iframe_sources(body, endpoint.url)

        mark_provider_failure(provider)
        errors.append(f"{provider.name}: {'; '.join(provider_errors)}")

    raise RuntimeError("; ".join(errors))


def fetch_ip_quality(
    ip: str,
    timeout: float,
    *,
    deadline: float | None = None,
) -> IPQuality:
    providers = quality_providers(ip)
    errors: list[str] = []
    for provider in providers:
        if provider_circuit_open(provider):
            errors.append(f"{provider.name}: {provider_skip_reason(provider)}")
            continue

        provider_errors: list[str] = []
        for endpoint in provider.endpoints:
            for referer in provider_endpoint_referers(endpoint, DEFAULT_PROBE_URL):
                try:
                    body = fetch_url_text(
                        endpoint.url,
                        timeout,
                        referer=referer,
                        deadline=deadline,
                    )
                except Exception as exc:  # noqa: BLE001
                    provider_errors.append(
                        f"{endpoint.url} via {referer_label(referer)}: {build_error_message(exc)}"
                    )
                    continue

                mark_provider_success(provider)
                return parse_scamalytics_quality(body, ip, endpoint.url)

        mark_provider_failure(provider)
        errors.append(f"{provider.name}: {'; '.join(provider_errors)}")

    raise RuntimeError("; ".join(errors))


def fetch_direct_ip_snapshot(
    probe_url: str,
    timeout: float,
    *,
    deadline: float | None = None,
) -> Snapshot:
    ip, source, error = fetch_plain_ip_from_providers(
        domestic_direct_providers(probe_url),
        timeout,
        probe_url,
        deadline=deadline,
    )
    if not ip:
        raise RuntimeError(f"Direct IP probe failed: {error or 'no provider returned an IP'}")

    snapshot = Snapshot(
        domestic=ip,
        foreign=None,
        google=None,
        fetched_at=now_iso(),
        source_url=source,
    )
    assign_section_result(snapshot, "domestic", ip, source=source)
    return snapshot


def fetch_snapshot(
    probe_url: str,
    timeout: float,
    *,
    quality_enabled: bool = True,
    quality_ip_allow_partial: bool = False,
    prefer_direct_ip: bool = False,
) -> Snapshot:
    deadline = probe_deadline(timeout)
    direct_error: str | None = None
    if prefer_direct_ip:
        # Pure IP-change mode tries direct public-IP probes first, then falls back to the HTML page if needed.
        try:
            snapshot = fetch_direct_ip_snapshot(
                probe_url,
                timeout,
                deadline=deadline,
            )
        except Exception as exc:  # noqa: BLE001
            direct_error = str(exc)
        else:
            stable_ip = snapshot.domestic
            if quality_enabled and stable_ip:
                try:
                    snapshot.ip_quality = fetch_ip_quality(
                        stable_ip,
                        timeout,
                        deadline=deadline,
                    )
                except Exception as exc:  # noqa: BLE001
                    snapshot.ip_quality_error = build_error_message(exc)
            return snapshot

    snapshot = Snapshot(
        domestic=None,
        foreign=None,
        google=None,
        fetched_at=now_iso(),
        source_url=probe_url,
    )

    domestic_ip, domestic_source, domestic_error = fetch_plain_ip_from_providers(
        domestic_direct_providers(probe_url),
        timeout,
        probe_url,
        deadline=deadline,
    )
    assign_section_result(snapshot, "domestic", domestic_ip, source=domestic_source, error=domestic_error)

    with ThreadPoolExecutor(max_workers=2) as executor:
        future_to_section = {
            executor.submit(
                fetch_plain_ip_from_providers,
                section_direct_providers(section, {}),
                timeout,
                probe_url,
                deadline=deadline,
            ): section
            for section in ("foreign", "google")
        }
        for future in as_completed(future_to_section):
            section = future_to_section[future]
            ip, source, error = future.result()
            assign_section_result(snapshot, section, ip, source=source, error=error)

    missing_sections = [section for section in ("domestic", "foreign", "google") if not getattr(snapshot, section)]
    if missing_sections:
        try:
            html_snapshot, iframe_sources = fetch_snapshot_from_html_providers(
                html_snapshot_providers(probe_url),
                timeout,
                probe_url,
                deadline=deadline,
            )
        except Exception as exc:  # noqa: BLE001
            if direct_error is not None:
                error_message = build_error_message(exc)
                raise RuntimeError(f"{direct_error}; HTML probe fallback failed: {error_message}") from exc
            html_error = build_error_message(exc)
            for section in missing_sections:
                existing_error = getattr(snapshot, _section_error_attr(section), None)
                combined_error = (
                    html_error
                    if not existing_error
                    else f"{existing_error}; html fallback: {html_error}"
                )
                setattr(snapshot, _section_error_attr(section), combined_error)
        else:
            if html_snapshot.source_url:
                snapshot.source_url = html_snapshot.source_url
            for section in missing_sections:
                value = getattr(html_snapshot, section)
                if value:
                    assign_section_result(snapshot, section, value, source=html_snapshot.source_url)

            iframe_missing_sections = [
                section for section in ("foreign", "google") if not getattr(snapshot, section)
            ]
            if iframe_missing_sections:
                with ThreadPoolExecutor(max_workers=len(iframe_missing_sections)) as executor:
                    future_to_section = {
                        executor.submit(
                            fetch_plain_ip_from_providers,
                            section_direct_providers(section, iframe_sources),
                            timeout,
                            probe_url,
                            deadline=deadline,
                        ): section
                        for section in iframe_missing_sections
                    }
                    for future in as_completed(future_to_section):
                        section = future_to_section[future]
                        ip, source, error = future.result()
                        assign_section_result(snapshot, section, ip, source=source, error=error)

    stable_ip = snapshot_consensus_ip(snapshot, allow_partial=quality_ip_allow_partial)
    if quality_enabled and stable_ip:
        try:
            snapshot.ip_quality = fetch_ip_quality(
                stable_ip,
                timeout,
                deadline=deadline,
            )
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


def snapshot_diagnostics(
    snapshot: Snapshot,
    *,
    sections: tuple[str, ...] = ("domestic", "foreign", "google"),
) -> list[str]:
    diagnostics: list[str] = []
    for section in sections:
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
    if not allow_partial:
        if not snapshot.foreign or not snapshot.google:
            return None
        if snapshot.foreign != snapshot.google:
            return None
        return snapshot.foreign

    values = [snapshot.domestic, snapshot.foreign, snapshot.google]
    available = [value for value in values if value]
    if not available:
        return None

    counts = Counter(available)
    candidate, occurrences = counts.most_common(1)[0]
    if occurrences > len(available) / 2:
        return candidate
    return None


def snapshot_change_ip(snapshot: Snapshot) -> Optional[str]:
    if snapshot.domestic:
        return snapshot.domestic
    if snapshot.foreign and snapshot.google and snapshot.foreign == snapshot.google:
        return snapshot.foreign
    return None
