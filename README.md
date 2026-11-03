# Mac Sentinel Synthesis Scanner

A single-file, dependency-free daily security report for macOS **standard (non-admin)**
accounts. It reads what's already visible to a normal user — no `sudo`, no third-party
Python packages, no network calls — and renders everything into one offline HTML
dashboard.

Built for people who don't have admin rights on their own Mac (managed/work machines,
shared family computers, etc.) but still want a daily sanity check on what's talking to
the network, whether Gatekeeper/FileVault/SIP are intact, and whether anything new has
wired itself into login items, shell profiles, cron, or browser extensions.

## What it checks

- **Network** — snapshots active connections and listening sockets via `lsof` and
  `nettop`. Flags connections to ports commonly associated with remote shells, Tor, or
  miners; binaries running from `/tmp`, `Downloads`, or other throwaway locations;
  processes going online for the first time; and large daily uploads. Routine
  all-interfaces listeners (Apple Continuity's `rapportd`, cloud-sync LAN discovery like
  `DropboxFileProvider`, etc.) are called out as `info`, not `medium` — visible, not
  alarming.
- **Host firewalls** — Little Snitch and Objective-See's LuLu: installed, running, and
  recent block events.
- **Gatekeeper / SIP / FileVault / firewall / XProtect** — reads posture via `spctl`,
  `csrutil`, `fdesetup`, and the Application Firewall, checks XProtect definition age,
  and audits `~/Downloads` and `~/Applications` for unsigned binaries or files whose
  quarantine flag was suspiciously stripped.
- **Endpoint scanners** — Malwarebytes, plus Objective-See's BlockBlock, OverSight,
  KnockKnock, and RansomWhere?, and ClamAV, if present: installed/running state and any
  readable threat/quarantine log lines.
- **Persistence watchdog** — fingerprints LaunchAgents/LaunchDaemons, shell profiles
  (`.zshrc` and friends), crontab, and Chrome/Brave/Edge/Arc/Firefox extensions against a
  saved baseline, and flags anything new, changed, or removed. Shell profiles are also
  scanned against a small set of known dropper/reverse-shell patterns.

Everything renders into one static HTML file with an embedded CSP (`default-src 'none'`)
and all dynamic content HTML-escaped — the report itself makes zero network requests.

## Requirements

- macOS with the Python 3 that ships with Apple's Command Line Tools (3.9+). No `pip`
  installs, no virtualenv.
- A standard (non-admin) account works fine; some checks (e.g. the unified log, raw
  packet capture) degrade gracefully without root instead of failing.

## Quick start

```bash
# One-off report
python3 mac_sentinel_synthesis_scanner.py report --open

# Preview the dashboard with sample data (no scanning, works on any OS)
python3 mac_sentinel_synthesis_scanner.py demo --open
```

## Running it on your Mac (standard account)

1. **Run the permission check first.** macOS gates access to folders like Downloads
   behind a privacy permission (TCC), separately from file permissions — this script
   just tells you up front which checks are already covered and which module would
   come back `partial` until you grant one:

   ```bash
   bash mac_sec_diagnostic.sh
   ```

   It's read-only: no `sudo`, no writes, no network calls. It only reports what it
   finds and, for anything missing, the exact Setting to open to fix it.

2. **Generate and open your live HTML report:**

   ```bash
   python3 mac_sentinel_synthesis_scanner.py report --open
   ```

   This writes a zero-dependency, offline HTML file to
   `~/MacSentinelSynthesisScanner/latest.html` (and archives daily copies in
   `~/MacSentinelSynthesisScanner/reports/`).

3. **Automate daily background collection (optional, no `sudo` required):**

   ```bash
   python3 mac_sentinel_synthesis_scanner.py install
   python3 mac_sentinel_synthesis_scanner.py rebaseline
   ```

   This installs two **user-level** LaunchAgents in `~/Library/LaunchAgents`: one that
   snapshots `lsof`/`nettop` every 15 minutes, and one that rebuilds `latest.html` every
   morning at 7:00 AM. `rebaseline` right after installing so the scanner's own new
   LaunchAgents don't show up as a "new persistence item" on the next report.

## Commands

| Command                       | What it does                                                         |
|--------------------------------|-----------------------------------------------------------------------|
| `sample`                       | Take one network snapshot (intended to run every 15 min)             |
| `report [--open] [--out PATH]` | Collect everything and write the HTML dashboard                     |
| `install [--hour H] [--interval M]` | Install two **user-level** LaunchAgents (sampler + daily report) |
| `uninstall`                    | Remove those LaunchAgents                                            |
| `rebaseline`                   | Accept the current persistence items as the new "known good"         |
| `resolve <ID...\|--all>`       | Mark finding(s) as resolved, so they stay hidden on future reports    |
| `unresolve <ID...\|--all>`     | Reopen previously resolved finding(s)                                |
| `demo [--out PATH] [--open]`   | Write a dashboard filled with sample data, for previewing the UI     |

`install` only writes to `~/Library/LaunchAgents` (no `/Library`, no `sudo`) and can be
fully undone with `uninstall`.

## Tracking findings over time

Every finding gets a stable ID (a short hash of its module, title, and evidence), so the
same underlying issue is recognized across report runs rather than treated as new each
time. For each finding, the dashboard tracks:

- **First seen** — the date it first appeared.
- **Days seen** — how many distinct days it's shown up.
- **New today** — flagged when a finding's first-seen date is today.

This state lives in `~/MacSentinelSynthesisScanner/state/findings_state.json` and is
updated on every `report` run — nothing here needs any action from you.

## Resolving findings ("dealt with")

Once you've reviewed a finding and decided it's expected (or you've fixed it), you can
mark it resolved so it drops out of future reports instead of nagging you daily. There
are two ways to do this, and they end up in the same place:

1. **From the terminal:**
   ```bash
   python3 mac_sentinel_synthesis_scanner.py resolve <ID>      # or --all
   python3 mac_sentinel_synthesis_scanner.py unresolve <ID>    # reopen it
   ```
2. **From the report itself** — click **Resolve** on any finding. This is purely
   client-side at first (saved to that browser's `localStorage`, so it survives closing
   the tab or reloading), with a sync bar showing how many changes are pending. From
   there, either:
   - Click **"Save to Synthesis Scanner"**, which downloads a small
     `mac-sentinel-synthesis-scanner-resolutions-<timestamp>.json` file to `~/Downloads`.
     The *next* time you run the script (any command), it's picked up automatically,
     merged into `findings_state.json`, and deleted — that's what actually makes a
     resolution "stick" across report runs or other browsers/devices.
   - Or click **"Copy Terminal command"** to copy the equivalent `resolve`/`unresolve`
     command instead, if you'd rather not have a browser download anything.

Because resolution state lives in `findings_state.json`, not inside any one HTML file,
dismissing a finding is permanent for that finding's identity (module + title +
evidence) — if the exact same issue is detected again later with different evidence
(e.g. a different IP address), it's treated as a new finding.

## Asking an AI about a finding

The report's findings are deliberately brief one-liners. When you want more — "what does this
actually mean, should I be worried?" — there are two ways to bring an AI assistant in, and neither
makes the tool itself send anything over the network.

### Copy for AI (works with anything, no setup)

Every finding has a **Copy for AI** button next to Resolve. It copies a short, pre-formatted
prompt — severity, area, title, detail, evidence, how long it's been seen, and your macOS version —
to your clipboard, ready to paste into Claude, ChatGPT, or a search engine. It's just a richer
version of what people already do by hand; nothing is sent anywhere until you paste it somewhere
yourself.

### MCP server (for Claude Desktop, Claude Code, or other MCP clients)

If you already use an AI assistant that supports [MCP](https://modelcontextprotocol.io/) (Model
Context Protocol), `mcp_server.py` lets it query your findings directly — "what are my
high-severity findings and what do they mean?" — with full context, instead of you pasting
anything in. There's no link to paste; MCP servers run locally and are wired up once in your AI
client's own settings, not shared as a URL.

It's read-only: it just parses the report data already embedded in
`~/MacSentinelSynthesisScanner/latest.html` (whatever the last `report`/`rebaseline` run produced).
It never runs a scan itself, never resolves or dismisses anything, and makes no network calls of
its own — the only network traffic involved is between you and your AI client, same as any other
conversation with it.

**One-time setup:**

1. Install the MCP SDK — the only part of this project with a third-party dependency, and only
   needed for this optional feature:
   ```bash
   pip3 install mcp
   ```
2. Add an entry to your AI client's MCP config pointing at the real, absolute path to
   `mcp_server.py` on your Mac. For Claude Desktop, that's
   `~/Library/Application Support/Claude/claude_desktop_config.json` (create it if it doesn't
   exist yet):
   ```json
   {
     "mcpServers": {
       "mac-sentinel-synthesis-scanner": {
         "command": "python3",
         "args": ["/absolute/path/to/mac-sentinel-synthesis-scanner/mcp_server.py"]
       }
     }
   }
   ```
3. Restart your AI client, then run a report at least once if you haven't already
   (`python3 mac_sentinel_synthesis_scanner.py report`) — the server has nothing to read until
   `latest.html` exists. After that, you can ask things like "check my Mac Sentinel findings" and
   your assistant will call `list_findings`, `get_finding`, or `report_summary` as needed.

## Where data lives

Everything is stored under `~/MacSentinelSynthesisScanner/` (`reports/` and `state/`).
Nothing is ever uploaded anywhere — there are no network calls in the collector or the
report template. Override the base directory with the `MAC_SENTINEL_SYNTHESIS_SCANNER_DIR`
environment variable if you'd rather it live somewhere else (e.g. inside an encrypted
volume).

## Known limitations

- Some checks (unified log queries, raw packet capture) need admin rights and silently
  fall back to a lower-fidelity source when run as a standard user; the dashboard's
  module status always says which mode it ran in.
- LuLu's plain-text log format/location is a best-effort guess (Little Snitch is read
  through its own documented CLI/JSON interface instead, which is more reliable).
- Keyword-based log matching (for Malwarebytes/Objective-See threat lines) is a
  heuristic, not a parser — it's tuned to avoid obvious false positives (e.g. matching
  "malware" inside the string "malwarebytes"), but new log formats from
  not-yet-tested tools may need similar tuning over time.
- The optional `mcp_server.py` (see "Asking an AI about a finding") is the one piece of this
  project with a third-party dependency (`pip install mcp`). The scanner and report itself
  remain dependency-free whether or not you ever use it.

## License

MIT — see [LICENSE](LICENSE).

## Author

[Brian Nibley](https://github.com/Brian-Nibley)
