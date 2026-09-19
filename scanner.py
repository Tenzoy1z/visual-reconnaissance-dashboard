"""
scanner.py — Network scanning backend for the Visual Reconnaissance Dashboard.

Provides target parsing, host discovery, port scanning, and banner grabbing
using only the Python standard library (socket + subprocess).  All heavy I/O
runs inside a ``ThreadPoolExecutor`` so a calling GUI thread never blocks.

No raw sockets or elevated privileges are required.
"""

from __future__ import annotations

import ipaddress
import logging
import re
import socket
import subprocess
import sys
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from threading import Event
from typing import Callable, Optional

from cve_lookup import CVEResult, lookup_cves


# ---------------------------------------------------------------------------
# Common ports used for lightweight host-discovery probes.
# These were chosen because they are almost always open on servers,
# desktops (RDP / SMB), or network equipment.
# ---------------------------------------------------------------------------
DISCOVERY_PORTS: list[int] = [
    80, 443, 22, 21, 25, 53, 135, 445, 3389, 8080,
]


# ---------------------------------------------------------------------------
# Data classes that hold scan results
# ---------------------------------------------------------------------------

@dataclass
class PortResult:
    """Stores the outcome of scanning a single port on a host.

    Attributes:
        port:    The TCP port number.
        is_open: Whether the port accepted a connection.
        banner:  Service banner captured via banner grabbing (may be empty).
        cves:    List of CVE records correlated from the banner (may be empty).
    """

    port: int
    is_open: bool
    banner: str = ""
    cves: list[CVEResult] = field(default_factory=list)


@dataclass
class HostResult:
    """Stores the outcome of scanning a single host.

    Attributes:
        ip:         The IPv4 address that was scanned.
        is_alive:   Whether the host responded to any discovery probe.
        open_ports: List of open ports found during the port-scan phase.
    """

    ip: str
    is_alive: bool
    open_ports: list[PortResult] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Target-parsing helpers
# ---------------------------------------------------------------------------

def parse_target(target: str) -> list[str]:
    """Convert a user-supplied target string into a list of IPv4 addresses.

    Supported formats
    -----------------
    * **Single IP**  — ``"192.168.1.1"``
    * **Dash range** — ``"192.168.1.1-254"``  (last octet range)
    * **CIDR**       — ``"192.168.1.0/24"``

    Returns:
        A list of IPv4 address strings.

    Raises:
        ValueError: If the input cannot be parsed into any supported format.
    """
    target = target.strip()
    if not target:
        raise ValueError("Target cannot be empty.")

    # --- CIDR notation (e.g. 10.0.0.0/24) ---
    if "/" in target:
        try:
            network = ipaddress.ip_network(target, strict=False)
            return [str(ip) for ip in network.hosts()]
        except ValueError:
            raise ValueError(f"Invalid CIDR notation: '{target}'.")

    # --- Dash range (e.g. 192.168.1.1-254) ---
    if "-" in target:
        pattern = r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.)(\d{1,3})-(\d{1,3})$"
        match = re.match(pattern, target)
        if not match:
            raise ValueError(
                f"Invalid range format: '{target}'. "
                "Expected something like 192.168.1.1-254."
            )
        base = match.group(1)
        start, end = int(match.group(2)), int(match.group(3))
        if not (0 <= start <= 255 and 0 <= end <= 255):
            raise ValueError("Octet values must be between 0 and 255.")
        if start > end:
            raise ValueError(
                f"Start of range ({start}) must be ≤ end ({end})."
            )
        return [f"{base}{i}" for i in range(start, end + 1)]

    # --- Single IP address ---
    try:
        ipaddress.ip_address(target)
        return [target]
    except ValueError:
        raise ValueError(
            f"'{target}' is not a valid IP address, range, or CIDR."
        )


# ---------------------------------------------------------------------------
# Low-level network probes
# ---------------------------------------------------------------------------

def _tcp_connect_check(ip: str, port: int, timeout: float = 0.5) -> bool:
    """Attempt a TCP three-way handshake to *ip*:*port*.

    This is the core primitive for both host discovery and port scanning.
    It requires **no** special privileges — just a normal ``SOCK_STREAM``
    socket with ``connect_ex``.

    Args:
        ip:      Target IPv4 address.
        port:    Target TCP port.
        timeout: Seconds to wait before giving up.

    Returns:
        ``True`` if the connection succeeded (port open / host alive),
        ``False`` on any error or timeout.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            return result == 0
    except (socket.error, OSError):
        return False


def _ping_check(ip: str, timeout: int = 1) -> bool:
    """Shell out to the OS ``ping`` command as a fallback discovery method.

    Uses ``-n 1`` on Windows and ``-c 1`` on POSIX to send a single ICMP
    echo request.  All output is suppressed to avoid console noise.

    Args:
        ip:      Target IPv4 address.
        timeout: Seconds to wait (converted to milliseconds for Windows).

    Returns:
        ``True`` if the ping process exits with code 0.
    """
    try:
        count_flag = "-n" if sys.platform == "win32" else "-c"
        timeout_flag = "-w" if sys.platform == "win32" else "-W"
        # Windows ``-w`` expects milliseconds; POSIX ``-W`` expects seconds.
        timeout_val = str(timeout * 1000) if sys.platform == "win32" else str(timeout)

        result = subprocess.run(
            ["ping", count_flag, "1", timeout_flag, timeout_val, ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout + 3,          # hard cap on the subprocess itself
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False


def discover_host(ip: str, timeout: float = 0.5) -> bool:
    """Determine whether *ip* is alive using unprivileged methods.

    Strategy (in order):
        1. Fast TCP-connect probes on common ports (very quick, works even
           when ICMP is blocked by a firewall).
        2. Fallback ICMP ping via ``subprocess`` in case all TCP ports are
           filtered but the host still responds to echo requests.

    Args:
        ip:      Target IPv4 address.
        timeout: Per-probe TCP timeout in seconds.

    Returns:
        ``True`` if the host responds to *any* probe.
    """
    for port in DISCOVERY_PORTS:
        if _tcp_connect_check(ip, port, timeout):
            return True
    return _ping_check(ip, timeout=1)


def scan_port(ip: str, port: int, timeout: float = 1.0) -> bool:
    """Check whether a single TCP *port* is open on *ip*.

    This is a thin wrapper around ``_tcp_connect_check`` with a slightly
    longer default timeout suitable for deliberate port scanning.

    Args:
        ip:      Target IPv4 address.
        port:    TCP port number (1–65 535).
        timeout: Seconds to wait for a connection.

    Returns:
        ``True`` if the port is open.
    """
    return _tcp_connect_check(ip, port, timeout)


def grab_banner(ip: str, port: int, timeout: float = 2.0) -> str:
    """Try to grab a service banner from *ip*:*port*.

    Connects, optionally sends a minimal probe (e.g. an HTTP ``HEAD``
    request), then reads up to 1 024 bytes of the response.

    Args:
        ip:      Target IPv4 address.
        port:    TCP port to banner-grab.
        timeout: Seconds to wait for data after connecting.

    Returns:
        The decoded banner string (first 1 024 bytes), or ``""`` on failure.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((ip, port))

            # HTTP ports: send a lightweight HEAD request to coax a response.
            if port in (80, 8080, 8443, 8888, 3000, 5000):
                sock.sendall(b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
            elif port == 443:
                # Raw sockets over TLS won't produce a readable banner.
                return ""
            else:
                # Many daemons (SSH, FTP, SMTP …) send a banner on connect.
                # Sending a newline can nudge silent services.
                sock.sendall(b"\r\n")

            data = sock.recv(1024)
            return data.decode("utf-8", errors="replace").strip()
    except (socket.error, OSError):
        return ""


# ---------------------------------------------------------------------------
# High-level scanner with threading and cooperative cancellation
# ---------------------------------------------------------------------------

class NetworkScanner:
    """Orchestrates host discovery → port scanning → banner grabbing.

    All heavy I/O runs inside a ``ThreadPoolExecutor``.  A
    ``threading.Event`` provides cooperative cancellation so the GUI can
    stop a scan at any time without killing threads unsafely.

    Typical usage::

        scanner = NetworkScanner(
            on_log=print,
            on_progress=lambda p: ...,
        )
        # Run on a background thread so the GUI stays responsive:
        threading.Thread(target=scanner.run, args=("10.0.0.0/24", 1, 1024)).start()
    """

    def __init__(
        self,
        on_log: Optional[Callable[[str], None]] = None,
        on_progress: Optional[Callable[[float], None]] = None,
        on_host_result: Optional[Callable[[HostResult], None]] = None,
        max_workers: int = 50,
        port_timeout: float = 1.0,
        banner_timeout: float = 2.0,
    ) -> None:
        """Initialise the scanner.

        Args:
            on_log:         Called with a human-readable status line whenever
                            something noteworthy happens (for the GUI text area).
            on_progress:    Called with a float in [0.0, 1.0] to drive a
                            progress bar.
            on_host_result: Called when scanning of a single host finishes,
                            with the completed ``HostResult``.
            max_workers:    Maximum concurrent threads in the pool.
            port_timeout:   Per-port TCP connect timeout (seconds).
            banner_timeout: Per-port banner-grab timeout (seconds).
        """
        self._on_log = on_log or (lambda _msg: None)
        self._on_progress = on_progress or (lambda _pct: None)
        self._on_host_result = on_host_result or (lambda _hr: None)
        self._max_workers = max_workers
        self._port_timeout = port_timeout
        self._banner_timeout = banner_timeout
        self._cancel_event = Event()
        self._results: list[HostResult] = []
        self._logger = logging.getLogger("scanner")

    # -- Public API ---------------------------------------------------------

    @property
    def results(self) -> list[HostResult]:
        """Return a shallow copy of the accumulated scan results."""
        return list(self._results)

    def cancel(self) -> None:
        """Signal all worker threads to stop as soon as possible."""
        self._cancel_event.set()
        self._log("⛔ Scan cancelled by user.")

    def run(self, target: str, start_port: int, end_port: int) -> None:
        """Execute a full scan: parse → discover → scan ports → banners.

        This method **blocks** until the scan finishes or is cancelled.
        Call it from a **background thread** to keep the GUI responsive.

        Args:
            target:     User-supplied target string (IP / range / CIDR).
            start_port: First port to scan (inclusive).
            end_port:   Last port to scan (inclusive).
        """
        self._cancel_event.clear()
        self._results.clear()

        # -- Parse target ----------------------------------------------------
        self._log(f"🔍 Parsing target: {target}")
        try:
            ips = parse_target(target)
        except ValueError as exc:
            self._log(f"❌ {exc}")
            return
        self._log(f"   → {len(ips)} address(es) to probe.")

        # -- Host discovery --------------------------------------------------
        self._log("📡 Starting host discovery …")
        live_hosts = self._discover_hosts(ips)
        if self._cancel_event.is_set():
            return
        self._log(f"   → {len(live_hosts)} live host(s) found.")

        if not live_hosts:
            self._log("ℹ️  No live hosts detected — nothing to scan.")
            self._on_progress(1.0)
            return

        # -- Port scan + banner grab -----------------------------------------
        total_ports = end_port - start_port + 1
        self._log(
            f"🔎 Scanning ports {start_port}–{end_port} "
            f"({total_ports} port(s)) on {len(live_hosts)} host(s) …"
        )
        self._scan_hosts(live_hosts, start_port, end_port)

        if not self._cancel_event.is_set():
            self._on_progress(1.0)
            self._log("✅ Scan complete.")

    # -- Internal helpers ---------------------------------------------------

    def _log(self, message: str) -> None:
        """Emit *message* to both the file logger and the GUI callback."""
        self._logger.info(message)
        self._on_log(message)

    def _discover_hosts(self, ips: list[str]) -> list[str]:
        """Probe every IP in *ips* concurrently and return the live ones.

        Progress is mapped to the range [0.0, 0.4] of the overall bar so
        the remaining 60 % is left for port scanning.
        """
        live: list[str] = []
        total = len(ips)
        done = 0

        with ThreadPoolExecutor(max_workers=self._max_workers) as pool:
            future_to_ip: dict[Future[bool], str] = {
                pool.submit(discover_host, ip): ip for ip in ips
            }
            for future in as_completed(future_to_ip):
                if self._cancel_event.is_set():
                    pool.shutdown(wait=False, cancel_futures=True)
                    return live

                ip = future_to_ip[future]
                try:
                    if future.result():
                        live.append(ip)
                        self._log(f"   ✅ {ip} is alive")
                except Exception as exc:
                    self._log(f"   ⚠️  Error probing {ip}: {exc}")

                done += 1
                self._on_progress(0.4 * done / total)

        return live

    def _scan_hosts(
        self, hosts: list[str], start_port: int, end_port: int
    ) -> None:
        """Scan the given port range on every host, grab banners, and report.

        Progress is mapped to the range [0.4, 1.0] of the overall bar.
        """
        ports = list(range(start_port, end_port + 1))
        total_work = len(hosts) * len(ports)
        done = 0

        with ThreadPoolExecutor(max_workers=self._max_workers) as pool:
            for host_ip in hosts:
                if self._cancel_event.is_set():
                    return

                host_result = HostResult(ip=host_ip, is_alive=True)

                # Submit all port-connect checks for this host at once.
                future_to_port: dict[Future[bool], int] = {
                    pool.submit(scan_port, host_ip, p, self._port_timeout): p
                    for p in ports
                }

                for future in as_completed(future_to_port):
                    if self._cancel_event.is_set():
                        pool.shutdown(wait=False, cancel_futures=True)
                        return

                    port = future_to_port[future]
                    try:
                        is_open = future.result()
                    except Exception as exc:
                        self._log(f"   ⚠️  Error scanning {host_ip}:{port} — {exc}")
                        is_open = False

                    if is_open:
                        banner = grab_banner(host_ip, port, self._banner_timeout)
                        port_result = PortResult(
                            port=port, is_open=True, banner=banner
                        )

                        banner_info = f" — {banner[:80]}" if banner else ""
                        self._log(f"   🟢 {host_ip}:{port} OPEN{banner_info}")

                        # --- CVE correlation ---
                        # Always log *something* for the CVE step so the
                        # user can tell the feature ran rather than being
                        # silently skipped.
                        if self._cancel_event.is_set():
                            # Scan is being cancelled — don't start new work.
                            pass
                        elif not banner:
                            # Ports like 135 (RPC) and 445 (SMB) speak
                            # binary protocols and won't return a readable
                            # text banner, so there's nothing to search for.
                            self._log(
                                "      🛡️  CVE lookup skipped "
                                "(no banner detected)"
                            )
                        else:
                            try:
                                cves = lookup_cves(banner)
                                port_result.cves = cves
                                if not cves:
                                    # lookup_cves() returns [] when the
                                    # banner couldn't be parsed into a
                                    # product + version string.
                                    self._log(
                                        "      🛡️  CVE lookup skipped "
                                        "(no product/version detected "
                                        "in banner)"
                                    )
                                else:
                                    for cve in cves:
                                        score_str = (
                                            f"{cve.score}"
                                            if cve.score is not None
                                            else "—"
                                        )
                                        # Flag low-confidence results so
                                        # the user knows they may be
                                        # coincidental keyword matches.
                                        if cve.confidence == "low":
                                            tag = "⚠ low confidence"
                                        else:
                                            tag = cve.severity
                                        self._log(
                                            f"      🛡️  {cve.cve_id}  "
                                            f"[{tag} / {score_str}]  "
                                            f"{cve.description}"
                                        )
                            except Exception as exc:
                                self._log(
                                    f"      ⚠️  CVE lookup failed for "
                                    f"{host_ip}:{port}: {exc}"
                                )

                        host_result.open_ports.append(port_result)

                    done += 1
                    self._on_progress(0.4 + 0.6 * done / total_work)

                # Sort open ports numerically before reporting.
                host_result.open_ports.sort(key=lambda pr: pr.port)
                self._results.append(host_result)
                self._on_host_result(host_result)

                # Log a per-host summary.
                count = len(host_result.open_ports)
                self._log(
                    f"   📋 {host_ip}: {count} open port(s) found."
                )

