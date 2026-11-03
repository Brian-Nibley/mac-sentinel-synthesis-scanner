#!/usr/bin/env python3
"""
mcp_server.py — optional MCP (Model Context Protocol) server for Mac Sentinel Synthesis Scanner.

Exposes the most recently generated report (~/MacSentinelSynthesisScanner/latest.html by default)
as a few read-only tools, so an MCP-aware AI assistant (Claude Desktop, Claude Code, etc.) can look
up and explain a finding directly instead of you copy-pasting it in. It only reads the report file
already on disk: it never runs a scan itself, never resolves or dismisses anything, and makes no
network calls of its own.

Requires: pip install mcp
This file is run by your AI client, not by hand — see README.md, "Asking an AI about a finding",
for setup.
"""
import json
import os
import re

from mcp.server.fastmcp import FastMCP

HOME = os.path.expanduser("~" + os.environ["SUDO_USER"]) if os.environ.get("SUDO_USER") else os.path.expanduser("~")
BASE_DIR = os.path.expanduser(os.environ.get("MAC_SENTINEL_SYNTHESIS_SCANNER_DIR") or os.path.join(HOME, "MacSentinelSynthesisScanner"))
REPORT_PATH = os.path.join(BASE_DIR, "latest.html")

mcp = FastMCP("mac-sentinel-synthesis-scanner")

_DATA_RE = re.compile(r'<script id="report-data" type="application/json">(.*?)</script>', re.DOTALL)
_SEV_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}
_FINDING_FIELDS = (
    "id", "severity", "module", "title", "detail", "evidence",
    "first_seen", "last_seen", "days_seen", "is_new", "resolved", "resolved_at",
)


def _load_report():
    try:
        with open(REPORT_PATH, encoding="utf-8", errors="replace") as fh:
            html = fh.read()
    except OSError:
        raise RuntimeError(
            "No report found at %s. On the Mac being monitored, run "
            "'python3 mac_sentinel_synthesis_scanner.py report' first, then try again." % REPORT_PATH
        )
    match = _DATA_RE.search(html)
    if not match:
        raise RuntimeError(
            "Could not find report data inside %s — it may be from an older version of the script." % REPORT_PATH
        )
    return json.loads(match.group(1).replace("<\\/", "</"))


def _finding_view(finding):
    return {key: finding.get(key) for key in _FINDING_FIELDS}


@mcp.tool()
def report_summary() -> dict:
    """Overview of the most recent Mac Sentinel Synthesis Scanner report: when it ran, which Mac,
    and how many open (unresolved) findings exist at each severity."""
    report = _load_report()
    findings = report.get("findings", [])
    open_findings = [f for f in findings if not f.get("resolved")]
    counts = {"high": 0, "medium": 0, "low": 0, "info": 0}
    for f in open_findings:
        counts[f.get("severity", "info")] = counts.get(f.get("severity", "info"), 0) + 1
    meta = report.get("meta", {})
    return {
        "generated_at": meta.get("generated_at"),
        "hostname": meta.get("hostname"),
        "macos_version": meta.get("macos_version"),
        "window_hours": meta.get("window_hours"),
        "open_findings_by_severity": counts,
        "resolved_findings": len(findings) - len(open_findings),
        "module_status": report.get("module_status", {}),
        "report_path": REPORT_PATH,
    }


@mcp.tool()
def list_findings(severity: str = "all", status: str = "open") -> list:
    """List findings from the most recent report, most urgent first.

    severity: "all" (default), "high", "medium", "low", or "info".
    status: "open" (default, not yet resolved), "resolved", or "all".
    """
    report = _load_report()
    findings = [_finding_view(f) for f in report.get("findings", [])]
    if status == "open":
        findings = [f for f in findings if not f.get("resolved")]
    elif status == "resolved":
        findings = [f for f in findings if f.get("resolved")]
    if severity != "all":
        findings = [f for f in findings if f.get("severity") == severity]
    findings.sort(key=lambda f: (_SEV_ORDER.get(f.get("severity"), 9), -(f.get("days_seen") or 0)))
    return findings


@mcp.tool()
def get_finding(finding_id: str) -> dict:
    """Full detail for one finding by its ID (the short ID shown in the report and used with the
    script's own `resolve`/`unresolve` commands)."""
    report = _load_report()
    for f in report.get("findings", []):
        if f.get("id") == finding_id:
            view = _finding_view(f)
            meta = report.get("meta", {})
            view["macos_version"] = meta.get("macos_version")
            view["hostname"] = meta.get("hostname")
            return view
    raise ValueError("No finding with id %r in the current report at %s." % (finding_id, REPORT_PATH))


if __name__ == "__main__":
    mcp.run()
