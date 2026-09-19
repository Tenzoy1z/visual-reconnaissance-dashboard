"""
dashboard.py — CustomTkinter GUI for the Visual Reconnaissance Dashboard.

This is the main entry point.  It wires up the ``NetworkScanner`` backend
to a modern dark-themed desktop UI with live result streaming, a progress
bar, and CSV / JSON export.

Run with::

    python dashboard.py
"""

from __future__ import annotations

import csv
import json
import logging
import threading
from datetime import datetime
from pathlib import Path
from tkinter import END, filedialog
from typing import Optional

import customtkinter as ctk

from scanner import HostResult, NetworkScanner

# ---------------------------------------------------------------------------
# Logging — one timestamped file per application session
# ---------------------------------------------------------------------------

LOG_DIR: Path = Path(__file__).resolve().parent / "logs"
LOG_DIR.mkdir(exist_ok=True)
LOG_FILE: Path = LOG_DIR / f"scan_{datetime.now():%Y%m%d_%H%M%S}.log"

# We explicitly create a FileHandler with encoding="utf-8" instead of using
# logging.basicConfig(filename=...).  On Windows the latter defaults to the
# system locale encoding (cp1252), which cannot represent emojis and other
# Unicode characters used in our log messages — they'd appear as escaped
# sequences (\U0001f50d) or replacement characters (�) in the log file.
_log_formatter = logging.Formatter(
    fmt="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
_file_handler = logging.FileHandler(str(LOG_FILE), encoding="utf-8")
_file_handler.setFormatter(_log_formatter)

_root_logger = logging.getLogger()
_root_logger.setLevel(logging.INFO)
_root_logger.addHandler(_file_handler)

_logger = logging.getLogger("dashboard")


# ---------------------------------------------------------------------------
# Main application class
# ---------------------------------------------------------------------------

class DashboardApp(ctk.CTk):
    """Top-level window for the Visual Reconnaissance Dashboard.

    Responsibilities:
        * Collect user input (target, port range).
        * Launch / cancel scans on a background thread via ``NetworkScanner``.
        * Display live log output in a scrolled text area.
        * Export results to CSV or JSON.
    """

    def __init__(self) -> None:
        """Create the window, configure the theme, and build all widgets."""
        super().__init__()

        self.title("Visual Reconnaissance Dashboard")
        self.geometry("960x680")
        self.minsize(780, 520)

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        # Internal state
        self._scanner: Optional[NetworkScanner] = None
        self._scan_thread: Optional[threading.Thread] = None
        self._results: list[HostResult] = []

        self._build_ui()

    # ------------------------------------------------------------------ UI
    def _build_ui(self) -> None:
        """Create every widget and lay them out using grid geometry.

        Layout (top → bottom):
            Row 0 — Input frame  (target entry + port-range entries)
            Row 1 — Button frame (Scan, Cancel, Export CSV, Export JSON)
            Row 2 — Progress bar
            Row 3 — Scrolled results text area  (expands to fill space)
            Row 4 — Status bar
        """
        # Allow the text area (row 3) to stretch vertically.
        self.columnconfigure(0, weight=1)
        self.rowconfigure(3, weight=1)

        # --- Row 0: Input frame -------------------------------------------
        input_frame = ctk.CTkFrame(self)
        input_frame.grid(row=0, column=0, sticky="ew", padx=12, pady=(12, 4))
        input_frame.columnconfigure(1, weight=1)          # target entry grows

        ctk.CTkLabel(input_frame, text="Target:").grid(
            row=0, column=0, padx=(12, 6), pady=10,
        )
        self._target_entry = ctk.CTkEntry(
            input_frame,
            placeholder_text="e.g.  192.168.1.1   192.168.1.1-254   10.0.0.0/24",
        )
        self._target_entry.grid(row=0, column=1, sticky="ew", padx=6, pady=10)

        ctk.CTkLabel(input_frame, text="Ports:").grid(
            row=0, column=2, padx=(12, 6), pady=10,
        )
        self._start_port_entry = ctk.CTkEntry(
            input_frame, width=72, placeholder_text="1",
        )
        self._start_port_entry.grid(row=0, column=3, padx=3, pady=10)

        ctk.CTkLabel(input_frame, text="–").grid(row=0, column=4, pady=10)

        self._end_port_entry = ctk.CTkEntry(
            input_frame, width=72, placeholder_text="1024",
        )
        self._end_port_entry.grid(row=0, column=5, padx=(3, 12), pady=10)

        # --- Row 1: Button frame ------------------------------------------
        btn_frame = ctk.CTkFrame(self)
        btn_frame.grid(row=1, column=0, sticky="ew", padx=12, pady=4)

        self._scan_btn = ctk.CTkButton(
            btn_frame, text="▶  Scan", width=120,
            command=self._on_scan, fg_color="#2fa572", hover_color="#27896a",
        )
        self._scan_btn.pack(side="left", padx=(12, 6), pady=10)

        self._cancel_btn = ctk.CTkButton(
            btn_frame, text="■  Cancel", width=120,
            command=self._on_cancel, state="disabled",
            fg_color="#c0392b", hover_color="#96281b",
        )
        self._cancel_btn.pack(side="left", padx=6, pady=10)

        self._csv_btn = ctk.CTkButton(
            btn_frame, text="📄  Export CSV", width=130,
            command=self._export_csv, state="disabled",
            fg_color="#2980b9", hover_color="#1f6fa0",
        )
        self._csv_btn.pack(side="left", padx=6, pady=10)

        self._json_btn = ctk.CTkButton(
            btn_frame, text="{ }  Export JSON", width=140,
            command=self._export_json, state="disabled",
            fg_color="#8e44ad", hover_color="#6c3483",
        )
        self._json_btn.pack(side="left", padx=6, pady=10)

        # --- Row 2: Progress bar ------------------------------------------
        self._progress = ctk.CTkProgressBar(self)
        self._progress.grid(row=2, column=0, sticky="ew", padx=12, pady=4)
        self._progress.set(0)

        # --- Row 3: Scrolled results text area ----------------------------
        self._results_text = ctk.CTkTextbox(
            self, wrap="word", font=ctk.CTkFont(family="Consolas", size=13),
        )
        self._results_text.grid(
            row=3, column=0, sticky="nsew", padx=12, pady=(4, 6),
        )

        # --- Row 4: Status bar --------------------------------------------
        self._status_label = ctk.CTkLabel(
            self, text=f"Log: {LOG_FILE}", anchor="w",
            font=ctk.CTkFont(size=11), text_color="gray",
        )
        self._status_label.grid(
            row=4, column=0, sticky="ew", padx=14, pady=(0, 8),
        )

    # --------------------------------------------------------- Input helpers

    def _get_port_range(self) -> tuple[int, int]:
        """Read the start/end port entries and clamp to valid bounds.

        Defaults to 1–1024 when the fields are empty or contain non-numeric
        text, so the user can just click *Scan* without filling them in.

        Returns:
            A ``(start, end)`` tuple guaranteed to satisfy
            ``1 <= start <= end <= 65535``.
        """
        try:
            start = int(self._start_port_entry.get())
        except ValueError:
            start = 1
        try:
            end = int(self._end_port_entry.get())
        except ValueError:
            end = 1024

        start = max(1, min(start, 65535))
        end = max(1, min(end, 65535))
        if start > end:
            start, end = end, start       # swap silently so the scan works
        return start, end

    # --------------------------------------------------------- Scan control

    def _on_scan(self) -> None:
        """Validate inputs, create a ``NetworkScanner``, and launch it.

        The scanner runs on a daemon thread so ``mainloop()`` isn't blocked.
        """
        target = self._target_entry.get().strip()
        if not target:
            self._append_text("❌ Please enter a target IP, range, or CIDR.\n")
            return

        start_port, end_port = self._get_port_range()

        # Reset the UI for a new scan.
        self._results_text.delete("1.0", END)
        self._results.clear()
        self._progress.set(0)

        self._scan_btn.configure(state="disabled")
        self._cancel_btn.configure(state="normal")
        self._csv_btn.configure(state="disabled")
        self._json_btn.configure(state="disabled")

        _logger.info(
            "Scan started — target=%s  ports=%d–%d", target, start_port, end_port,
        )

        # Create a fresh scanner wired to our thread-safe GUI callbacks.
        self._scanner = NetworkScanner(
            on_log=self._threadsafe_log,
            on_progress=self._threadsafe_progress,
            on_host_result=self._threadsafe_host_result,
        )

        self._scan_thread = threading.Thread(
            target=self._run_scan,
            args=(target, start_port, end_port),
            daemon=True,
        )
        self._scan_thread.start()

    def _run_scan(self, target: str, start_port: int, end_port: int) -> None:
        """Entry point for the background scan thread.

        Wraps ``scanner.run()`` in a try/except so unexpected errors surface
        in the GUI instead of silently dying.
        """
        try:
            assert self._scanner is not None
            self._scanner.run(target, start_port, end_port)
        except Exception as exc:
            self._threadsafe_log(f"❌ Unexpected error: {exc}")
            _logger.exception("Unhandled exception in scan thread")
        finally:
            # Re-enable buttons on the main (Tk) thread.
            self.after(0, self._scan_finished)

    def _scan_finished(self) -> None:
        """Called on the main thread after the scan thread exits.

        Collects results from the scanner and toggles button states.
        """
        if self._scanner is not None:
            self._results = self._scanner.results

        self._scan_btn.configure(state="normal")
        self._cancel_btn.configure(state="disabled")

        # Enable export only when there is something worth exporting.
        has_data = any(hr.open_ports for hr in self._results)
        export_state = "normal" if has_data else "disabled"
        self._csv_btn.configure(state=export_state)
        self._json_btn.configure(state=export_state)

        _logger.info("Scan finished — %d host result(s).", len(self._results))

    def _on_cancel(self) -> None:
        """Signal the running scanner to stop."""
        if self._scanner is not None:
            self._scanner.cancel()

    # ------------------------------------------------- Thread-safe callbacks

    def _threadsafe_log(self, message: str) -> None:
        """Schedule a text-area append from any thread.

        ``self.after(0, ...)`` posts the call to the Tk event loop, which
        is the only safe way to touch widgets from a non-main thread.
        """
        self.after(0, self._append_text, message + "\n")

    def _threadsafe_progress(self, value: float) -> None:
        """Schedule a progress-bar update from any thread."""
        self.after(0, self._progress.set, value)

    def _threadsafe_host_result(self, _host_result: HostResult) -> None:
        """Called when a single host's scan is complete.

        Results are collected centrally from ``scanner.results`` in
        ``_scan_finished``, so this callback is intentionally a no-op.
        It exists as a hook for future per-host GUI updates (e.g. a table).
        """

    def _append_text(self, text: str) -> None:
        """Insert *text* at the bottom of the results box and auto-scroll.

        This must only be called on the main Tk thread (see
        ``_threadsafe_log``).
        """
        self._results_text.insert(END, text)
        self._results_text.see(END)

    # ------------------------------------------------------------ Export

    def _flat_results(self) -> list[dict[str, object]]:
        """Flatten scan results into one dict per open port.

        Each row includes CVE correlation data as semicolon-delimited
        strings so they fit naturally into a single CSV row.

        Returns:
            A list of dicts with keys ``host``, ``port``, ``state``,
            ``banner``, ``cve_ids``, ``cve_severities``, ``cve_scores``,
            and ``cve_descriptions``.
        """
        rows: list[dict[str, object]] = []
        for hr in self._results:
            for pr in hr.open_ports:
                # Collapse the list of CVEResult objects into flat strings
                # for tabular export.  Use ";" as delimiter so commas inside
                # descriptions don't break CSV.
                cve_ids = "; ".join(c.cve_id for c in pr.cves) if pr.cves else ""
                cve_severities = (
                    "; ".join(c.severity for c in pr.cves) if pr.cves else ""
                )
                cve_scores = (
                    "; ".join(
                        str(c.score) if c.score is not None else "—"
                        for c in pr.cves
                    )
                    if pr.cves
                    else ""
                )
                cve_descs = (
                    "; ".join(c.description for c in pr.cves) if pr.cves else ""
                )
                cve_conf = (
                    "; ".join(c.confidence for c in pr.cves) if pr.cves else ""
                )

                rows.append({
                    "host": hr.ip,
                    "port": pr.port,
                    "state": "open",
                    "banner": pr.banner,
                    "cve_ids": cve_ids,
                    "cve_severities": cve_severities,
                    "cve_scores": cve_scores,
                    "cve_descriptions": cve_descs,
                    "cve_confidence": cve_conf,
                })
        return rows

    # CSV / JSON column order for exports.
    _EXPORT_FIELDS: list[str] = [
        "host", "port", "state", "banner",
        "cve_ids", "cve_severities", "cve_scores", "cve_descriptions",
        "cve_confidence",
    ]

    def _export_csv(self) -> None:
        """Open a Save-As dialog and write scan results to a CSV file."""
        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            title="Export results to CSV",
        )
        if not path:
            return                         # user cancelled the dialog

        rows = self._flat_results()
        try:
            with open(path, "w", newline="", encoding="utf-8") as fh:
                writer = csv.DictWriter(fh, fieldnames=self._EXPORT_FIELDS)
                writer.writeheader()
                writer.writerows(rows)
            self._append_text(f"📄 Results exported to {path}\n")
            _logger.info("Exported CSV → %s (%d rows)", path, len(rows))
        except OSError as exc:
            self._append_text(f"❌ CSV export failed: {exc}\n")
            _logger.error("CSV export failed: %s", exc)

    def _export_json(self) -> None:
        """Open a Save-As dialog and write scan results to a JSON file."""
        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            title="Export results to JSON",
        )
        if not path:
            return

        rows = self._flat_results()
        try:
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(rows, fh, indent=2, ensure_ascii=False)
            self._append_text(f"📄 Results exported to {path}\n")
            _logger.info("Exported JSON → %s (%d entries)", path, len(rows))
        except OSError as exc:
            self._append_text(f"❌ JSON export failed: {exc}\n")
            _logger.error("JSON export failed: %s", exc)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    """Launch the Visual Reconnaissance Dashboard."""
    _logger.info("Application started.")
    app = DashboardApp()
    app.mainloop()
    _logger.info("Application closed.")


if __name__ == "__main__":
    main()

