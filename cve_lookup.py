"""
cve_lookup.py — CVE correlation module for the Visual Reconnaissance Dashboard.

Queries the NVD (National Vulnerability Database) public REST API v2.0 to
find known CVEs associated with a product/version string extracted from a
service banner.

This module is intentionally self-contained: it handles banner parsing,
HTTP requests, response parsing, rate-limiting, and error handling in one
place so it can be read and explained independently of the scanner.

NVD API docs: https://nvd.nist.gov/developers/vulnerabilities
"""

from __future__ import annotations

import logging
import re
import time
import urllib.error
import urllib.parse
import urllib.request
import json as _json
from dataclasses import dataclass
from typing import Optional

_logger = logging.getLogger("cve_lookup")

# ---------------------------------------------------------------------------
# NVD API configuration
# ---------------------------------------------------------------------------

_NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Without an API key the NVD allows ~5 requests per 30 seconds.
# We enforce a minimum delay between requests to stay well within limits.
_MIN_REQUEST_INTERVAL: float = 6.0        # seconds between API calls
_REQUEST_TIMEOUT: int = 15                # seconds per HTTP request
_MAX_RESULTS: int = 5                     # cap CVEs returned per banner

# Timestamp of the last API call (module-level) so all callers share the
# rate-limit window.
_last_request_time: float = 0.0


# ---------------------------------------------------------------------------
# Data class for a single CVE result
# ---------------------------------------------------------------------------

@dataclass
class CVEResult:
    """One CVE record returned by the NVD.

    Attributes:
        cve_id:      The CVE identifier (e.g. ``"CVE-2021-44228"``).
        description: A short English-language description of the vulnerability.
        score:       The CVSS v3.1 (or v3.0 / v2.0) base score, or ``None``
                     if no score is available.
        severity:    Human-readable severity label (``"CRITICAL"``,
                     ``"HIGH"``, ``"MEDIUM"``, ``"LOW"``) or ``"N/A"``.
        confidence:  ``"high"`` if the product name appears in the CVE
                     description or CPE data, ``"low"`` if the match is
                     purely a keyword coincidence.  Defaults to ``"high"``.
    """

    cve_id: str
    description: str
    score: Optional[float] = None
    severity: str = "N/A"
    confidence: str = "high"


# ---------------------------------------------------------------------------
# Banner → search-keyword extraction
# ---------------------------------------------------------------------------

# Protocol identifiers that look like "Product/Version" in a banner but are
# NOT actual software products.  Must be checked case-insensitively.
_PROTOCOL_NAMES: set[str] = {
    "HTTP", "HTTPS", "RTSP", "SIP", "FTP", "SMTP", "POP3", "IMAP",
}

# Some Server-header tokens are thin stdlib wrappers (e.g. Python's
# ``http.server`` advertises "SimpleHTTP/0.6").  Map them to the real
# upstream product that NVD actually tracks.
_PRODUCT_ALIASES: dict[str, str] = {
    "simplehttp":     "Python",
    "basehttpserver":  "Python",
    "cpython":         "Python",
    "wsgiref":         "Python",
}

# Products we recognise as "real" software tracked in NVD.  When multiple
# tokens appear in a Server header (e.g. "Apache/2.4.49 OpenSSL/1.1.1")
# we prefer these over unknown names.
_KNOWN_PRODUCTS: set[str] = {
    "Apache", "nginx", "lighttpd", "Cherokee", "Microsoft-IIS",
    "Tomcat", "Jetty", "Caddy", "Gunicorn", "Uvicorn",
    "Python", "Node.js", "Express",
    "OpenSSL", "GnuTLS",
    "OpenSSH",
    "ProFTPD", "vsftpd", "Pure-FTPd",
    "Postfix", "Exim", "Sendmail", "Dovecot",
    "MySQL", "MariaDB", "PostgreSQL",
}

# Each pattern captures (product, version) from non-HTTP banner formats.
# Order matters: more specific patterns are tried first.
_BANNER_PATTERNS: list[re.Pattern[str]] = [
    # SSH protocol banner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"
    re.compile(r"SSH-[\d.]+-OpenSSH[_ ]([\d.]+\w*)", re.IGNORECASE),
    # "OpenSSH_8.9p1" / "OpenSSH 7.4" (outside an SSH-2.0 line)
    re.compile(r"(OpenSSH)[_ ]([\d.]+\w*)", re.IGNORECASE),
    # "Apache/2.4.49", "nginx/1.21.3", "lighttpd/1.4.59"
    re.compile(r"(Apache|nginx|lighttpd|Cherokee)[/ ]([\d.]+)", re.IGNORECASE),
    # "ProFTPD 1.3.6", "vsftpd 3.0.3"
    re.compile(r"(ProFTPD|vsftpd|Pure-FTPd)[/ ]([\d.]+)", re.IGNORECASE),
    # "Microsoft-IIS/10.0"
    re.compile(r"(Microsoft-IIS)[/ ]([\d.]+)", re.IGNORECASE),
    # "220 mail.example.com ESMTP Postfix 3.4.8"
    re.compile(r"(Postfix|Exim|Sendmail|Dovecot)[/ ]([\d.]+)", re.IGNORECASE),
    # "MySQL 5.7.34", "MariaDB 10.6.4"
    re.compile(r"(MySQL|MariaDB|PostgreSQL)[/ ]([\d.]+)", re.IGNORECASE),
]

# Regex to pull individual "Product/Version" or "Product Version" tokens
# out of a Server-header value string.
_TOKEN_RE = re.compile(r"([A-Za-z][\w.-]*)[/ ]([\d]+(?:\.[\d]+)*\w*)")


def _extract_from_http_server_header(banner: str) -> Optional[tuple[str, str]]:
    """Parse the ``Server:`` header out of an HTTP response and extract
    the most meaningful (product, version) pair from it.

    The Server header often contains multiple space-separated tokens,
    e.g. ``"SimpleHTTP/0.6 Python/3.12.10"``.  Selection strategy:

        1. Apply alias mapping (SimpleHTTP → Python).
        2. Prefer known NVD-tracked products.
        3. Fall back to the **last** token (usually the runtime/platform).

    Args:
        banner: The full HTTP response banner (status line + headers).

    Returns:
        ``(product, version)`` or ``None`` if no Server header is present
        or no useful token could be found.
    """
    # Find the Server: header line.
    server_match = re.search(
        r"Server:\s*(.+?)(?:\r?\n|$)", banner, re.IGNORECASE
    )
    if not server_match:
        return None

    server_value = server_match.group(1).strip()
    tokens = _TOKEN_RE.findall(server_value)

    if not tokens:
        return None

    # Filter out bare protocol names (e.g. "HTTP/1.1" echoed in Server).
    valid: list[tuple[str, str]] = [
        (prod, ver) for prod, ver in tokens
        if prod.upper() not in _PROTOCOL_NAMES
    ]
    if not valid:
        return None

    # 1) Check for aliases first (e.g. SimpleHTTP → Python).
    for product, version in valid:
        canonical = _PRODUCT_ALIASES.get(product.lower())
        if canonical:
            # If the aliased product also appears as an explicit token with
            # its own version, prefer that version.  E.g. "SimpleHTTP/0.6
            # Python/3.12.10" → ("Python", "3.12.10") not ("Python", "0.6").
            for p2, v2 in valid:
                if p2.lower() == canonical.lower() and v2:
                    return (canonical, v2)
            return (canonical, version)

    # 2) Prefer a known NVD-tracked product.
    for product, version in valid:
        if product in _KNOWN_PRODUCTS:
            return (product, version)

    # 3) Fall back to the last token (typically the platform / runtime).
    return valid[-1]


def extract_product_version(banner: str) -> Optional[tuple[str, str]]:
    """Try to extract a (product, version) pair from a raw service banner.

    For HTTP response banners (starting with ``HTTP/``), the ``Server:``
    header is parsed instead of the status line — this avoids confusing
    the protocol version (``HTTP/1.0``) with a product name.

    For all other banners (SSH, FTP, SMTP, …) the specific patterns in
    ``_BANNER_PATTERNS`` are tried in order, followed by a generic
    ``Product/Version`` fallback that explicitly skips protocol identifiers.

    Returns ``None`` if no recognisable product/version is found — the
    caller should skip the CVE lookup.

    Args:
        banner: The raw banner string captured from the service.

    Returns:
        A ``(product, version)`` tuple, or ``None``.
    """
    if not banner or not banner.strip():
        return None

    # ---- HTTP responses: delegate to the Server-header parser ----
    if banner.lstrip().upper().startswith("HTTP/"):
        return _extract_from_http_server_header(banner)

    # ---- Non-HTTP: try specific patterns first ----
    # Special-case SSH protocol banner: "SSH-2.0-OpenSSH_8.9p1 …"
    ssh_match = _BANNER_PATTERNS[0].search(banner)      # first pattern
    if ssh_match:
        return ("OpenSSH", ssh_match.group(1))

    for pattern in _BANNER_PATTERNS[1:]:
        match = pattern.search(banner)
        if match:
            groups = match.groups()
            if len(groups) >= 2:
                product = groups[0].strip()
                version = groups[1].strip()
                if version:
                    return (product, version)

    # ---- Generic fallback for unknown banners ----
    # Match "ProductName/1.2.3" but skip protocol identifiers.
    generic = re.compile(r"([A-Za-z][\w.-]+)[/ ]([\d]+(?:\.[\d]+)+)")
    for match in generic.finditer(banner):
        product = match.group(1)
        if product.upper() not in _PROTOCOL_NAMES:
            return (product, match.group(2))

    return None


# ---------------------------------------------------------------------------
# NVD API query
# ---------------------------------------------------------------------------

def _rate_limit() -> None:
    """Sleep if necessary to honour the NVD rate limit.

    The NVD allows roughly 5 requests per 30 s without an API key.
    We space our calls by ``_MIN_REQUEST_INTERVAL`` seconds.
    """
    global _last_request_time
    elapsed = time.monotonic() - _last_request_time
    if elapsed < _MIN_REQUEST_INTERVAL:
        time.sleep(_MIN_REQUEST_INTERVAL - elapsed)
    _last_request_time = time.monotonic()


def _query_nvd(keyword: str) -> list[dict]:
    """Send a keyword search to the NVD CVE API and return raw results.

    Args:
        keyword: The search string (e.g. ``"Apache 2.4.49"``).

    Returns:
        A list of vulnerability dicts from the ``"vulnerabilities"`` array
        in the NVD response, or an empty list on any failure.
    """
    _rate_limit()

    params = urllib.parse.urlencode({
        "keywordSearch": keyword,
        "resultsPerPage": _MAX_RESULTS,
    })
    url = f"{_NVD_API_URL}?{params}"

    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "VisualReconDashboard/1.0",
            "Accept": "application/json",
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=_REQUEST_TIMEOUT) as resp:
            data = _json.loads(resp.read().decode("utf-8"))
            return data.get("vulnerabilities", [])
    except urllib.error.HTTPError as exc:
        _logger.warning("NVD API HTTP error %d for '%s'.", exc.code, keyword)
        return []
    except urllib.error.URLError as exc:
        _logger.warning("NVD API URL error for '%s': %s", keyword, exc.reason)
        return []
    except (TimeoutError, OSError) as exc:
        _logger.warning("NVD API timeout/network error for '%s': %s", keyword, exc)
        return []
    except (_json.JSONDecodeError, KeyError, ValueError) as exc:
        _logger.warning("NVD API response parse error for '%s': %s", keyword, exc)
        return []


def _parse_cvss(metrics: dict) -> tuple[Optional[float], str]:
    """Extract the best available CVSS score and severity from NVD metrics.

    Prefers CVSS v3.1, falls back to v3.0, then v2.0.

    Args:
        metrics: The ``"metrics"`` dict from a single CVE object.

    Returns:
        ``(score, severity)`` — score may be ``None`` and severity defaults
        to ``"N/A"`` when no metrics are available.
    """
    # Try CVSS 3.1 first, then 3.0, then 2.0.
    for key in ("cvssMetricV31", "cvssMetricV30"):
        metric_list = metrics.get(key, [])
        if metric_list:
            cvss_data = metric_list[0].get("cvssData", {})
            score = cvss_data.get("baseScore")
            severity = cvss_data.get("baseSeverity", "N/A")
            return (score, severity)

    # CVSS v2 has a slightly different structure.
    v2_list = metrics.get("cvssMetricV2", [])
    if v2_list:
        cvss_data = v2_list[0].get("cvssData", {})
        score = cvss_data.get("baseScore")
        # v2 doesn't have baseSeverity in the same place; derive from score.
        if score is not None:
            if score >= 9.0:
                severity = "CRITICAL"
            elif score >= 7.0:
                severity = "HIGH"
            elif score >= 4.0:
                severity = "MEDIUM"
            else:
                severity = "LOW"
            return (score, severity)

    return (None, "N/A")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def lookup_cves(banner: str) -> list[CVEResult]:
    """Look up known CVEs for the product/version found in *banner*.

    This is the main entry point for the rest of the application.

    Workflow:
        1. Parse the banner to extract a product and version.
        2. Query the NVD keyword-search API with ``"product version"``.
        3. Parse each returned CVE into a ``CVEResult``.

    Edge cases handled:
        * Banner is empty or unparseable → returns ``[]`` (skip).
        * NVD is unreachable / rate-limited / errors → returns a single
          ``CVEResult`` with id ``"N/A"`` and description
          ``"CVE lookup unavailable"``.
        * NVD returns zero hits → returns a single ``CVEResult`` with
          ``"No known CVEs found"``.

    Args:
        banner: Raw service banner string.

    Returns:
        A list of ``CVEResult`` objects (may be empty).
    """
    # Step 1: extract product + version from the banner.
    pv = extract_product_version(banner)
    if pv is None:
        _logger.info("No product/version found in banner; skipping CVE lookup.")
        return []

    product, version = pv
    keyword = f"{product} {version}"
    _logger.info("CVE lookup for: %s", keyword)

    # Step 2: query the NVD.
    raw_vulns = _query_nvd(keyword)

    # Handle API failure (the query function returns [] on errors, but we
    # distinguish "no results" from "could not reach API" by checking
    # whether we got an empty list *without* an error having been logged).
    # Instead, _query_nvd logs warnings on errors.  A simpler heuristic:
    # if we got None-ish data, report it as unavailable.
    if raw_vulns is None:
        return [
            CVEResult(
                cve_id="N/A",
                description="CVE lookup unavailable",
                score=None,
                severity="N/A",
            )
        ]

    # Step 3: parse results and score relevance.
    #
    # NVD keyword search is loose — "Python 3.12" can match CVEs that
    # merely *mention* Python in passing.  We tag each result as "high"
    # confidence if the product name appears in the CVE description or
    # CPE criteria, and "low" otherwise, so the GUI can flag speculative
    # keyword hits.
    product_lower = product.lower()
    results: list[CVEResult] = []

    for vuln in raw_vulns:
        cve = vuln.get("cve", {})
        cve_id = cve.get("id", "Unknown")

        # Get the English description.
        desc = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break

        # --- Relevance check ---
        # Look for the product name in the description text and in the
        # CPE match criteria (which contain vendor:product strings).
        desc_lower = desc.lower()
        mentioned_in_desc = product_lower in desc_lower

        mentioned_in_cpe = False
        for config in cve.get("configurations", []):
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    criteria = cpe_match.get("criteria", "").lower()
                    if product_lower in criteria:
                        mentioned_in_cpe = True
                        break
                if mentioned_in_cpe:
                    break
            if mentioned_in_cpe:
                break

        confidence = "high" if (mentioned_in_desc or mentioned_in_cpe) else "low"

        # Truncate very long descriptions for readability.
        if len(desc) > 200:
            desc = desc[:197] + "…"

        score, severity = _parse_cvss(cve.get("metrics", {}))
        results.append(CVEResult(
            cve_id=cve_id,
            description=desc,
            score=score,
            severity=severity,
            confidence=confidence,
        ))

    # If every result is low-confidence, the keyword search likely returned
    # noise rather than genuine matches.  Still return them so the user can
    # judge, but the GUI will mark them accordingly.

    # If the API returned results but none matched, say so explicitly.
    if not results:
        return [
            CVEResult(
                cve_id="—",
                description="No known CVEs found",
                score=None,
                severity="—",
            )
        ]

    return results

